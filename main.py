import datetime
import tkinter as tk
import uuid
from PIL import ImageTk, Image
import json
import os
import sqlite3
import boto3
import botocore
from sqlite3 import Error
import hashlib
import re

import pathlib
from typing import Optional
import math, sys
from pathlib import Path
from botocore.exceptions import ClientError

stree_verison_key = "stree_version"
lock_basename = '.sync.lock'
remote_path = lambda key: "{0}/{1}".format(config['remote']['bucket'], key)
skip_empty_objects = lambda o: True if o['Key'].endswith('/') and o['Size'] == 0 else False
parent = lambda string: string.rpartition('/')[0]
key_from_path = lambda path: path.replace(slash(config['remote']['bucket']), "", 1)
current_timestamp = lambda: str(datetime.datetime.now(datetime.timezone.utc).timestamp())

def absolute_path(path):
    path = config['local_path'] + path

    if os.name == 'nt':
        path = path.replace("/", "\\\\")

    return path


def just_print(msg, to_gui_also=True):
    global text_area

    local_datetime = datetime.datetime.now()
    msg = str(local_datetime) + " - " + msg                

    print(msg)

    if to_gui_also:
        text_area.insert(tk.INSERT, msg + "\n")
        text_area.update()
        text_area.see("end")

def debug(msg, to_gui_also=True):
    if config['debug']:
        just_print(msg, to_gui_also)

def object_type(o):
    if 'IsDirectory' in o or (o['Key'].endswith('/') and o['Size'] == 0):
        return "directory"

    return "file"

def on_top_path(path):
    tmp_split = path.split("/")
    if '' in tmp_split:
        tmp_split.remove('')

    if len(tmp_split) == 0:
        return True

    return False

def get_local_etag(path: str, chunk_size_bytes: Optional[int] = None) -> str:
    """Calculates an expected AWS s3 upload etag for a local on-disk file.
    Takes into account multipart uploads, but does NOT account for additional encryption
    (like KMS keys)
    """
    path = pathlib.Path(path)

    if chunk_size_bytes is None:
        # This is used by `aws s3 cp` function
        file_size = path.stat().st_size
        chunk_size_bytes = 8 * 1024 * 1024  # 8 MB
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
        while math.ceil(file_size / chunk_size_bytes) > 10000:  #
            chunk_size_bytes *= 2

    md5s = []

    with open(path, "rb") as fp:
        while True:
            data = fp.read(chunk_size_bytes)
            if not data:
                break
            md5s.append(hashlib.md5(data))

    if len(md5s) > 1:  # We are dealing with a multipart upload
        digests = b"".join(m.digest() for m in md5s)
        multipart_md5 = hashlib.md5(digests)
        expected_etag = f'"{multipart_md5.hexdigest()}-{len(md5s)}"'
    elif len(md5s) == 1:  # File smaller than chunk size
        expected_etag = f'"{md5s[0].hexdigest()}"'
    else:  # Empty file
        expected_etag = f'"{hashlib.md5().hexdigest()}"'

    return expected_etag.replace('"', '')

def clear_logo():
    panel.pack_forget()

def list_remote_objects(prefix=None, delimiter=None, remove_prefix=True):
    objects = []

    paginator = s3.get_paginator("list_objects_v2")
    response = paginator.paginate(Bucket=config['remote']['bucket'], PaginationConfig={"PageSize": 1000}, Prefix=prefix, Delimiter=delimiter)
    for page in response:
        tmp_objects = []

        if 'CommonPrefixes' in page:
            for cp in page['CommonPrefixes']:         
                tmp_objects.append({
                    'Key': cp['Prefix'],
                    'IsDirectory': True
                })

        if 'Contents' in page:
            tmp_objects = tmp_objects + page['Contents']

        for t in tmp_objects:
            t['remote_path'] = remote_path(t['Key'])

        if remove_prefix:
            tmp = []
            for t in tmp_objects:
                if t['Key'] == prefix:
                    continue
                tmp.append(t)

            objects = objects + tmp

            continue        

        objects = objects + tmp_objects

    return objects

def list_local_folders_in_db(path):
    path_depth = path.count("/")
    path_depth_plus_one = path_depth + 1
    path += "%"
    sql = 'select id, path, path_depth, version, local_etag, remote_etag, type from files where path like ? and (path_depth = ? or (path_depth = ? and type = "directory"))'
    cursor = db.cursor()
    result = cursor.execute(sql, [path, path_depth, path_depth_plus_one])
    row = result.fetchall()
    debug("getting row from path {0}: {1}".format(path, row))

    return row

def set_remote_key_based_on_local_path(path):
    key = path.replace(config['local_path'], "", 1)
    key = key.replace(slash(config['remote']['bucket']), "", 1)

    if os.name == "nt":
        key = re.sub(r'(\\+)', '/', key)

    return key

def list_local_folders(path):
    entries = []

    for entry in os.scandir(path):
        # maybe use re.sub for replacement, because you could easily fuckup object names
        tmp = {
            "absolute_path": entry.path,
            "Key": set_remote_key_based_on_local_path(entry.path), # this is actually relative path
            "type": "directory" if entry.is_dir() else "file"
        }
        tmp['remote_path'] = remote_path(tmp['Key'])

        if tmp['type'] == "directory":
            tmp['absolute_path'] = slash(tmp['absolute_path'])
            tmp['Key'] = just_slash(tmp['Key'])
            tmp['remote_path'] = just_slash(tmp['remote_path'])

        entries.append(tmp)

    return entries

def get_remote_version(key):
    debug("about to get remote version with key {0}".format(key))

    try:
        response = s3.get_object_tagging(
            Bucket=config['remote']['bucket'],
            Key=key
        )

        if response:
            found = ""
            for tag in response['TagSet']:
                if tag['Key'] == stree_verison_key:
                    found = tag['Value']
                    break

            if found == "":
                found = set_remote_version(key)

            return found
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            return None

    debug("ERROR: getting tag {2} of an object {0} in bucket {1}".format(key, config['remote']['bucket'], stree_verison_key))

    return None

def set_remote_version(key, now=None):
    debug("we are about to set remote version for key {0}".format(key))

    if now is None:
        now = current_timestamp()

    response = s3.put_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key,
        Tagging={
            "TagSet": [
                {
                    'Key': stree_verison_key,
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    debug("ERROR: setting tag {2} for an object {0} in bucket {1} and version".format(key, config['remote']['bucket'], stree_verison_key))

    return None

def get_remote_bucket_version():
    debug("getting remote bucket version")

    try:
        response = s3.get_bucket_tagging(
            Bucket=config['remote']['bucket'],
        )

        if response:
            found = ""
            for tag in response['TagSet']:
                if tag['Key'] == stree_verison_key:
                    found = tag['Value']
                    break

            if found == "":
                found = set_remote_bucket_version()

                if not found:
                    debug("ERROR: setting tag {1} for bucket {0}".format(config['remote']['bucket'], stree_verison_key))
                    return None

            debug("remote bucket version {0}".format(found))

            return found
    except ClientError:
        debug("could not get tags for bucket {0}, so we try to set it".format(config['remote']['bucket']))
        found = set_remote_bucket_version()

        if found:
            return found

    just_print("ERROR: getting tag {1} of a bucket {0}".format(config['remote']['bucket'], stree_verison_key))

    return None

def set_remote_bucket_version(now=None):
    if now is None:
        now = current_timestamp()

    debug("setting {0} bucket version to {1}".format(config['remote']['bucket'], now))

    response = s3.put_bucket_tagging(
        Bucket=config['remote']['bucket'],
        Tagging={
            "TagSet": [
                {
                    'Key': stree_verison_key,
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    debug("ERROR: setting tag {1} for bucket {0}".format(config['remote']['bucket'], stree_verison_key))

    return None

def file_from_db(path):
    debug("getting file info from db with path {0}".format(path))
    
    sql = 'select id, path, version, local_etag from files where path = ?'
    cursor = db.cursor()
    result = cursor.execute(sql, ([path]))
    row = result.fetchone()
    
    debug("got row from path {0}: {1}".format(path, row))
    return row

def posix_path(path):
    path = path.replace("\\", "/")

    return path

def os_path(path):
    if os.name == "nt":
        path = path.replace("/", "\\")

    return path


def download_remote_file(o, delete_existing=True):
    key = o['Key']

    debug("about to download file/directory from key {0}".format(key))

    remote_version = get_remote_version(key)
    if remote_version is None:
        just_print("could not get remote version")
        return

    version = {
        config['local_device_name']: remote_version,
        config['remote']['host']: remote_version
    }

    remote_path = o['remote_path'];

    remote_etag = ""
    local_etag = ""
    path_depth = remote_path.count("/")
    absolute_path = config['local_path'] + os_path(remote_path)

    debug("will download to {0}".format(absolute_path))    
    debug("remote path {0}".format(remote_path))    

    if object_type(o) == "file":
        # this is file, so we should download it
        debug("this is file, so we are doing actual download")

        remote_etag = o['ETag'].replace('"', "")
        # we create local dir if it not exists
        local_dir = os.path.dirname(absolute_path)
        if not os.path.exists(local_dir):
            debug("creating directory {0} for file {1}".format(local_dir, remote_path))

            os.makedirs(local_dir)

        if delete_existing and os.path.isfile(absolute_path):
            debug("we are deleting file {0} so we can download it afterwards".format(absolute_path))
            os.remove(absolute_path)

        if not skip_empty_objects(o):
            i = 0
            while True:
                try:
                    debug("just before actual download")                
                    # because of https://github.com/boto/boto3/issues/3781 we cannot use the following line
                    # s3.download_file(config['remote']['bucket'], key, absolute_path). instead we have to
                    # use get_object and do it in chunks
                    obj = s3.get_object(
                        Bucket=config['remote']['bucket'],
                        Key=key
                    )
                    with open(f"{absolute_path}", 'wb') as f:
                        for chunk in obj['Body'].iter_chunks(chunk_size=4096):
                            f.write(chunk)                    

                    break
                except Exception as e:
                    if i == 3:
                        raise 

                    debug(str(e))
                    debug("failed to download. try number: {0}".format(i))

                    i += 1                    

            local_etag = get_local_etag(absolute_path)
    else:
        debug("this is directory")

        if not os.path.exists(absolute_path):
            debug("creating directory {0}".format(absolute_path))

            os.makedirs(absolute_path)

    debug("local etag {0}".format(local_etag))
    debug("remote etag {0}".format(remote_etag))
    debug("type {0}".format(object_type(o)))

    if object_type(o) == "file" and local_etag != remote_etag:
        just_print("probably we should not be here. etags should be the same. got local etag and remote etag")

    if file_from_db(remote_path) is None:
        sql = "insert into files(path, path_depth, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (remote_path, path_depth, json.dumps(version), object_type(o), local_etag, remote_etag))
        db.commit()
    else:
        sql = "update files set version = ?, local_etag = ?, remote_etag = ? where path = ?"
        cursor = db.cursor()
        cursor.execute(sql, (json.dumps(version), local_etag, remote_etag, remote_path))
        db.commit()

def get_remote_etag(key):
    response = s3.head_object(
        Bucket=config['remote']['bucket'],
        Key=key,
    )
    if response:
        return response['ETag'].replace("\"", "")

    return None

def remote_key_exists(key):
    debug("checking if remote key {0} exists".format(key))

    try:
        s3.head_object(Bucket=config['remote']['bucket'], Key=key)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False

        debug("we should not be here")
        debug(e)

    return True

def upload_local_file(o, delete_existing=False):
    key = o['Key']
    path = remote_path(key)

    debug("about to upload file/directory {0} to key {1}".format(o['absolute_path'], key))

    remote_etag = ""
    local_etag = ""

    remote_version = ""
    version = {
        config['local_device_name']: get_local_version(path),
        config['remote']['host']: remote_version
    }

    if o["type"] == "file":
        # this is file, so we should upload it
        debug("this is file, so we are doing actual upload")

        s3.upload_file(o['absolute_path'], config['remote']['bucket'], key)
        version[config['remote']['host']] = set_remote_version(key)
        version[config['local_device_name']] = version[config['remote']['host']]
        local_etag = get_local_etag(o['absolute_path'])
        remote_etag = get_remote_etag(key)

    else:
        debug("this is directory")
            # todo

    if config['debug']:
        print("local etag {0}".format(local_etag))
        print("remote etag {0}".format(remote_etag))
        if o['type'] == "file" and local_etag != remote_etag:
            print("we should not be here. etags should be the same. got local etag and remote etag")
        print("type {0}".format(o['type']))

    if file_from_db(path) is None:
        path_depth = path.count("/")

        sql = "insert into files(path, path_depth, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (path, path_depth, json.dumps(version), o['type'], local_etag, remote_etag))
        db.commit()
    else:
        sql = "update files set version = ?, local_etag = ?, remote_etag = ? where path = ?"
        cursor = db.cursor()
        cursor.execute(sql, (json.dumps(version), local_etag, remote_etag, path))
        db.commit()

def get_local_bucket_version():
    path = just_slash(config['remote']['bucket'])

    debug("getting local bucket version for path {0}".format(path))

    sql = "select version from files where path = ?"
    cursor = db.cursor()
    result = cursor.execute(sql, [(path)])
    row = result.fetchone()

    debug("local bucket version {0}".format(row['version']))

    return json.loads(row['version'])

def get_local_version(path):
    sql = 'select version, status from files where path = ?'
    cursor = db.cursor()
    result = cursor.execute(sql, [(path)])
    row = result.fetchone()

    if row:
        version = json.loads(row['version'])

        changed = False
        if config['local_device_name'] not in version:
            version['local_device_name'] = ""
            changed = True

        if config['remote']['host'] not in version:
            version['remote']['host'] = ""
            changed = True

        if changed:
            sql = 'update files set version = ? where path = ?'
            cursor = db.cursor()
            cursor.execute(sql, [json.dumps(version), path])
            db.commit()

        return version

    return None

def check_remote_paths_for_its_existence(path):
    debug("checking path '{0}' for its existence".format(path))

    if not path or path == "":
        return

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        path = slash(path)

        debug("splitted_path: {0}".format(splitted_path))

        try:
            response = s3.head_object(
                Bucket=config['remote']['bucket'],
                Key=path)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                debug("no path object exists, so we create one")
                s3.put_object(Bucket=config['remote']['bucket'], Key=path, Body='')
        except Exception as e:
            just_print("we should not be here")
            just_print(e)

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

def check_remote_paths_versions(path):
    debug("we set versions to paths which do not have set versions")
    debug("we are about to check remote paths for versions starting at {0}".format(path))

    if not path or path == "":
        return

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        path = just_slash(path)

        debug("splitted_path: {0}".format(splitted_path))

        get_remote_version(path)

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

    get_remote_bucket_version()

def update_remote_parent_versions(path, same_real_datetime_update=False, skip_existing=False):
    debug("we are about to update version for path {0}".format(path))

    if not path or path == "":
        return

    now = None
    if same_real_datetime_update:
        now = current_timestamp()

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        path = just_slash(path)

        debug("splitted_path: {0}".format(splitted_path))

        set_remote_version(path, now)

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

    set_remote_bucket_version(now)

# but watch out, if for some reason remote version does not exist, we create it
def update_local_parent_versions(path, same_real_datetime_update=True):
    debug("about to update local parent version with path {0}".format(path))

    if not path or path == "":
        return

    now = None
    if same_real_datetime_update:
        now = current_timestamp()

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        path = just_slash(path)

        debug("checking path for its existence {0}".format(path))
        debug("splitted_path: {0}".format(splitted_path))

        full_remote_path = remote_path(path)
        remote_version = get_remote_version(path)
        local_version = get_local_version(full_remote_path)

        if local_version is not None:
            if local_version[config['remote']['host']] != remote_version:
                local_version[config['remote']['host']] = remote_version
            if local_version[config['local_device_name']] == "":
                local_version[config['local_device_name']] = now

            sql = 'update files set version = ? where path = ?'
            cursor = db.cursor()
            cursor.execute(sql, [json.dumps(local_version), full_remote_path])
            db.commit()

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

    remote_bucket_version = get_remote_bucket_version()
    local_bucket_version = get_local_bucket_version()

    if local_bucket_version is not None:
        changed = False
        path = just_slash(config['remote']['bucket'])

        if local_bucket_version[config['remote']['host']] != remote_bucket_version:
            local_bucket_version[config['remote']['host']] = remote_bucket_version
            changed = True

        if local_bucket_version[config['local_device_name']] == "":
            local_bucket_version[config['local_device_name']] = now
            changed = True

        if changed:
            sql = 'update files set version = ? where path = ?'
            cursor = db.cursor()
            cursor.execute(sql, [json.dumps(local_bucket_version), path])
            db.commit()

def utc_to_float(utc_string):
    return datetime.datetime.strptime(utc_string, "%Y-%m-%d %H:%M:%S.%f").timestamp()

def just_slash(string):
    if not string.endswith("/"):
        string = string + "/"

    return string

def slash(string):
    if os.name == 'nt':
        if not string.endswith("\\"):
            string = string + "\\"
    else:
        if not string.endswith("/"):
            string = string + "/"

    return string

def check_bucket_changes():
    _remote_version = get_remote_bucket_version()
    _local_version = get_local_bucket_version()

    if _remote_version is None:
        just_print("could not get remote bucket version for bucket {0}".format(config['remote']['bucket']))
        return None

    if _local_version is None:
        just_print("could not get local bucket version for bucket {0}".format(config['remote']['bucket']))
        return None

    local_version_device = 0 if _local_version[config['local_device_name']] == '' else float(_local_version[config['local_device_name']])
    local_version_remote = 0 if _local_version[config['remote']['host']] == '' else float(_local_version[config['remote']['host']])
    remote_version = 0 if _remote_version == '' else float(_remote_version)

    changed_locally = False
    if local_version_device > local_version_remote:
        changed_locally = True

    changed_remotely = False
    if remote_version > local_version_remote:
        changed_remotely = True

    return {
        "locally": changed_locally,
        "remotely": changed_remotely
    }

def check_object_changes(o):
    path = remote_path(o['Key'])

    debug("checking object/file/dir changes for path {0}".format(path))

    _remote_version = get_remote_version(o['Key'])
    _local_version = get_local_version(path)

    if _remote_version is None or _local_version is None:
        just_print("could not get remote version for key {0} or local version {1}".format(o['Key'], path))
        return None

    local_version_device = _local_version[config['local_device_name']]
    local_version_remote = _local_version[config['remote']['host']]

    changed_locally = False
    if ((local_version_device is not None and local_version_remote is not None) and
            local_version_device > local_version_remote):
        changed_locally = True

    changed_remotely = False
    if ((_remote_version is not None and local_version_remote is not None) and
            _remote_version > local_version_remote):
        changed_remotely = True

    if changed_locally:
        debug("{0} changed_locally".format(path))
    if changed_remotely:
        debug("{0} changed_remotely".format(path))

    return {
        "locally": changed_locally,
        "remotely": changed_remotely
    }

# here we check for local file changes based on current and previous etag calculations.
# this should be put into separate worker, thread or something, outside of this program.
# however, then our source of "authority" will be probably db
def check_for_local_file_changes(o):
    path = remote_path(o['Key'])
    f = file_from_db(path)
    current_local_etag = get_local_etag(o['absolute_path'])
    if current_local_etag != f['local_etag']:
        version = json.loads(f['version'])
        version[config['local_device_name']] = current_timestamp()
        sql = 'update files set version = ?, local_etag = ? where path = ?'
        cursor = db.cursor()
        cursor.execute(sql, [(json.dumps(version), current_local_etag, o['Key'])])
        db.commit()

    update_local_parent_versions(parent(o['Key']))

def delete_in_db(path):
    debug("deleting path {0} in db".format(path))

    sql = 'delete from files where path = ?'
    cursor = db.cursor()
    cursor.execute(sql, [(path)])
    db.commit()

def delete_on_remote(key):
    debug("deleting path {0} on remote".format(remote_path(key)))

    response = s3.delete_object(
        Bucket=config['remote']['bucket'],
        Key=key,
    )

    return response

def dir_is_empty(path):
    with os.scandir(path) as it:
        if any(it):
            return False

    return True

def delete_on_local(path):
    debug("deleting path {0} on local".format(path))

    if os.path.isfile(path):
        debug("path {0} is file, so we delete it".format(path))
        os.remove(path)

    if os.path.isdir(path) and dir_is_empty(path):
        debug("path {0} is dir and is empty, so we delete it".format(path))
        os.rmdir(path)

    if os.path.isdir(path) and not dir_is_empty(path):
        debug("path {0} is dir and is not empty".format(path))
        return path

    return None


def list_all_files_in_db():
    debug("listing all files in db with path other than {0}".format(just_slash(config['remote']['bucket'])))

    sql = 'select id, path, version from files where path <> ?'
    cursor = db.cursor()
    result = cursor.execute(sql, [(just_slash(config['remote']['bucket']))])
    rows = result.fetchall()

    return rows

def bucket_exists():
    try:
        s3.head_bucket(Bucket=config['remote']['bucket'])
    except ClientError:
        debug("bucket {0} does not exists".format(config['remote']['bucket']))

        return False
    
    return True

def create_bucket():
    debug("creating bucket {0}".format(config['remote']['bucket']))

    try:
        s3.create_bucket(Bucket=config['remote']['bucket'])
    except ClientError as e:
        debug("ERROR: could not create bucket {0}".format(config['remote']['bucket']))
        debug(e)

        return False
    
    return True

def list_all_files_on_remote():
    debug("listing all files on remote")

    if not bucket_exists():
        create_bucket()

    tmp = []
    result = list_remote_objects('', '', False)
    
    for r in result:
        tmp.append(r['remote_path'])

    return tmp

def sanitize(path: pathlib.Path):
    tmp = str(path)

    if path.is_dir():
        tmp = slash(tmp)
    tmp = tmp.replace(config['local_path'], "", 1)

    return tmp

def list_all_files_on_local():
    debug("listing all files on local path {0}".format(config['local_path']))

    tmp = list(Path(config['local_path']).rglob("*"))
    # we get relative paths
    tmp = list(map(sanitize, tmp))
    # we remove root (bucket) from list

    if len(tmp) == 0:
        return []
    
    i = 0
    for t in tmp:
        if t == config['remote']['bucket']:
            break

    del tmp[i]

    if os.name == 'nt':
        tmp = list(map(lambda x: posix_path(x), tmp))

    return tmp

# function returns probably deleted objects on remote
def check_remote():
    just_print("--- START CHECKING REMOTE ---")
    i = 0
    remote_todo = list_remote_objects(prefix="", delimiter="/")
    while i < len(remote_todo):
        o = remote_todo[i]
        i += 1

        if object_type(o) == "directory":
            path = o['remote_path']
            debug("checking remote directory with path: {0}".format(path))
            if file_from_db(path) is None:
                debug("remote directory with path: {0} not in local db, we should add it".format(path))

                check_remote_paths_for_its_existence(parent(o['Key']))
                check_remote_paths_versions(parent(o['Key']))
                download_remote_file(o)
                update_local_parent_versions(parent(o['Key']))

                tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                remote_todo.extend(tmp)
            else:
                # if remote version differs from local version, we add it to todo list
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    just_print("ERROR: CONFLICT: key {0} of path {1} changed locally and remotely".format(o['Key'], path))
                    continue

                if changed["locally"] or changed["remotely"]:
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    check_remote_paths_versions(parent(o['Key']))
                    tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                    remote_todo.extend(tmp)

        # if remote does exist but local does not, get or create it
        if object_type(o) == "file":
            path = o['remote_path']

            debug("checking remote object {0}".format(o))
            debug("checking file with path: {0}".format(path))

            if file_from_db(path) is None:
                # 1. check if there was a new file added
                debug("local file with path: {0} not in db, we should add it".format(path))
                check_remote_paths_for_its_existence(parent(o['Key']))
                check_remote_paths_versions(parent(o['Key']))
                download_remote_file(o)
                update_local_parent_versions(parent(o['Key']))
            else:
                # 2. check if file was updated
                # if remote version differs from local version, we update it
                tmp = {
                    "absolute_path": absolute_path(o['remote_path']),
                    "Key": o['Key'],
                    "type": "file"
                }
                check_for_local_file_changes(tmp)
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    just_print("ERROR: CONFLICT: key {0} of path {1} changed locally and remotely".format(o['Key'], path))
                    continue

                if changed["locally"]:
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    upload_local_file(tmp)
                    update_remote_parent_versions(parent(o['Key']))

                if changed["remotely"]:
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    check_remote_paths_versions(parent(o['Key']))
                    download_remote_file(o)
                    update_local_parent_versions(parent(o['Key']))

    just_print("--- END CHECKING REMOTE ---")

# this is far from perfect
# for POC we are now just listing through all files and directories locally to see if there were some changes.
# we should do this with external service written in c, rust, go... catching inotify or something.
def check_local():
    just_print("--- START CHECKING LOCAL ---")
    i = 0
    local_todo = list_local_folders(os.path.join(config['local_path'], config['remote']['bucket']))
    while i < len(local_todo):
        o = local_todo[i]
        i += 1

        if o["type"] == "directory":
            debug("checking local directory with path: {0}".format(o["absolute_path"]))

            if file_from_db(o['remote_path']) is None:
                debug("directory with key {0} and path {1} not in db, we should add it".format(o['Key'], o["absolute_path"]))

                check_remote_paths_for_its_existence(o["Key"])
                check_remote_paths_versions(parent(o['Key']))
                upload_local_file(o)
                update_remote_parent_versions(parent(o['Key']))
                update_local_parent_versions(parent(o['Key']))
                tmp = list_local_folders(o["absolute_path"])
                local_todo.extend(tmp)
            else:
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    just_print("ERROR: CONFLICT: directory {0} changed locally and remotely".format(o['Key']))
                    continue

                if changed["locally"] or changed["remotely"]:
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    check_remote_paths_versions(parent(o['Key']))
                    tmp = list_local_folders(o["absolute_path"])
                    local_todo.extend(tmp)
        else:
            debug("checking remote object {0}".format(o))

            if file_from_db(o['remote_path']) is None:
                # 1. check if there was a new file added
                debug("local file with path: {0} not in db, we should add it".format(o['absolute_path']))

                if remote_key_exists(o['Key']):
                    just_print(
                        "ERROR: CONFLICT: we try to add local file to remote, but remote file with key {0} already exists".format(
                            o['Key']))
                    continue

                check_remote_paths_for_its_existence(parent(o['Key']))
                check_remote_paths_versions(parent(o['Key']))
                upload_local_file(o)
                update_remote_parent_versions(parent(o['Key']), True)
            else:
                # 2. check if file was updated
                # if remote version differs from local version, we update it
                check_for_local_file_changes(o)
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    just_print("ERROR: CONFLICT: key {0} changed locally and remotely".format(o['Key']))
                    continue

                if changed["locally"]:
                    tmp = {
                        "absolute_path": o['absolute_path'],
                        "Key": o['Key'],
                        "type": "file"
                    }
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    upload_local_file(tmp)
                    update_remote_parent_versions(parent(o['Key']), True)

                if changed["remotely"]:
                    check_remote_paths_for_its_existence(parent(o['Key']))
                    check_remote_paths_versions(parent(o['Key']))
                    download_remote_file(o)
                    update_local_parent_versions(parent(o['Key']))

    just_print("--- END CHECKING LOCAL ---")

def check_deleted():
    just_print("--- START CHECKING FOR DELETED FILES ---")

    start = datetime.datetime.now(datetime.timezone.utc)
    debug("we'll try to find files which were deleted on local or on remote")
    debug("start finding and deleting files: {0}".format(start.strftime("%Y-%m-%d %H:%M:%S.%f")))

    files = {}
    files['db'] = list_all_files_in_db()
    files['remote'] = list_all_files_on_remote()
    files['local'] = list_all_files_on_local()

    to_delete = []
    for file_in_db in files['db']:
        path = file_in_db['path']
        debug("scanning changes for path {0}".format(path))

        if not path in files['local'] and not path in files['remote']:
            delete_in_db(path)
        elif not path in files['local'] and path in files['remote']:
            version = json.loads(file_in_db['version'])
            remote_version = get_remote_version(key_from_path(path))

            if remote_version is None:
                debug("could not get remote version for path {0}".format(path))
                continue
            if version[config['remote']['host']] == remote_version:
                delete_on_remote(key_from_path(path))
                delete_in_db(path)
                continue

            debug("CONFLICT: remote or local version got updated, so we cannot delete {0}".format(path))
        elif path in files['local'] and not path in files['remote']:
            # maybe not needed
            # version = json.loads(file_in_db['version'])
            # if version[config['remote']['host']] == version[config['local_device_name']]:
            for_later = delete_on_local(absolute_path(path))
            if for_later:
                to_delete.append(for_later)

            delete_in_db(path)

    # sometimes dirs are not empty, so we have to delete them later, or now :)
    debug("before to delete empty folders")
    for t in to_delete:
        debug("trying to delete \"later\" folder {0}".format(t))
        if dir_is_empty(t):
            debug("dir {0} is empty. deleting".format(t))
            os.rmdir(t)

    end = datetime.datetime.now(datetime.timezone.utc)
    diff = end - start

    debug("end finding and deleting files: {0}".format(end.strftime("%Y-%m-%d %H:%M:%S.%f")))
    debug("time diff: {0}".format(diff))

    just_print("--- END CHECKING FOR DELETED FILES ---")

def count_files(dir):
    return len([1 for x in list(os.scandir(dir)) if x.is_file()])

def acquire_sync_lock():
    global lock_objectname

    try:
        lock_objectname = f"{lock_basename}.{uuid.uuid4()}"        
        debug(f"creating lock {lock_objectname} in bucket {config['remote']['bucket']}")
        s3.put_object(Bucket=config['remote']['bucket'], Key=lock_objectname, Body='')
        remote_locks = list_remote_objects(f'{lock_basename}', '/')
        sorted_by_lastmodified = sorted(remote_locks, key=lambda x: x['LastModified'], reverse=True)
        for s in sorted_by_lastmodified:
            print(f"{s['Key']} {s['LastModified']}")
        if sorted_by_lastmodified[0]['Key'] == lock_objectname:
            return True    

        response = s3.delete_object(Bucket=config['remote']['bucket'], Key=lock_objectname)
        if not (response and 'ResponseMetadata' in response):
            debug(f"could not delete lock {lock_objectname}")

        debug(f"successfully deleted lock {lock_objectname}")        
        
        return False
    except Exception as e:
        debug(f"could not aquire lock with {lock_objectname}")
        debug(e)

    return False

def sync():
    global sync_pause, db

    debug("just before sync")

    if sync_pause:
        debug("sync paused. waiting for {0} seconds".format(config['sync_time']))
        root.after(1000 * config['sync_time'], sync)
        return
    
    if not acquire_sync_lock():
        debug("other sync in progress. waiting for {0} seconds".format(config['sync_time']))
        root.after(1000 * config['sync_time'], sync)
        return

    debug("syncing after {0}s".format(config['sync_time']))

    sql = 'select count(*) as count from files'
    cursor = db.cursor()
    result = cursor.execute(sql)
    row = result.fetchone()
    debug("we have {0} files in local db".format(row['count']))

    # if this is first run of the program, then we populate local db with remote "data"
    # we do not require "lock" for first usage
    if row['count'] == 0:
        if not os.path.exists(config['local_path']):
            msg = "ERROR: local directory {0} for storing files should exist".format(config['local_path'])
            debug(msg)
            return

        if count_files(config['local_path']) > 0:
            debug("ERROR: local path should be empty on first run")
            return

        local_bucket_dir = os.path.join(config['local_path'], config['remote']['bucket'])
        if not os.path.exists(local_bucket_dir):
            debug("creating local bucket directory {0}".format(local_bucket_dir))
            os.makedirs(local_bucket_dir)

        # we insert bucket path
        bucket_init_version = {
            config['remote']['host']: "",
            config['local_device_name']: ""
        }

        sql = "insert into files(path, path_depth, version, type) values (?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (config['remote']['bucket'] + "/", 1, json.dumps(bucket_init_version), "directory"))
        db.commit()

        i = 0
        remote_todo = list_remote_objects(prefix="", delimiter="/")
        while i < len(remote_todo):
            o = remote_todo[i]
            i += 1

            debug(str(o))

            if object_type(o) == "directory":
                tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                remote_todo.extend(tmp)

            check_remote_paths_for_its_existence(parent(o['Key']))
            check_remote_paths_versions(parent(o['Key']))
            download_remote_file(o)
            update_local_parent_versions(parent(o['Key']))

        root.after(1000 * config['sync_time'], sync)

        return

    check_deleted()

    changed_bucket = check_bucket_changes()
    if changed_bucket["locally"] and changed_bucket["remotely"]:
        just_print("local AND remote files has been changed, this is possible CONFLICT, however let us try to sync anyway")

    if changed_bucket["remotely"]:
        check_remote()

    # todo: until we implement some watcher of changed files, we do full local scan every time
    # https://github.com/gorakhargosh/watchdog/
    check_local()

    if config['debug']:
        debug("--- AT THE END --- ")

        files = {}
        files['db'] = list_all_files_in_db()
        files['remote'] = list_all_files_on_remote()
        files['local'] = list_all_files_on_local()

        debug("len db without root: {0}".format(len(files['db'])))
        debug("len remote without root: {0}".format(len(files['remote'])))
        debug("len local without root: {0}".format(len(files['local'])))

        debug("--- AT THE END --- ")

    response = s3.delete_object(Bucket=config['remote']['bucket'], Key=lock_objectname)
    if not (response and 'ResponseMetadata' in response):
        debug(f"could not delete lock {lock_objectname}")

    debug(f"successfully deleted lock {lock_objectname}")

    root.after(1000 * config['sync_time'], sync)

def get_db():
    conn = None
    try:
        conn = sqlite3.connect('stree.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        sql = 'create table if not exists files(id integer primary key autoincrement, path varchar(255) unique, path_depth integer, version varchar(255), type varchar(9), remote_etag varchar(32), local_etag varchar(32), status varchar(7))'
        cursor.execute(sql)

        sql = 'create table if not exists info(key varchar(20) primary key, value varchar(50))'
        cursor.execute(sql)
        conn.commit()
    except Error as e:
        just_print(e)

    return conn

def toggle_pause_sync(event):
    global sync_pause

    caller = event.widget

    if sync_pause:
        sync_pause = False
        debug("unpausing sync")
        caller.config(text='Pause sync')
    else:
        sync_pause = True
        debug("pausing sync")
        caller.config(text='Unpause sync')

def main_gui():
    global root, text_area, pause_sync_button

    text_area = tk.Text(root)
    scrollbar = tk.Scrollbar(root, command=text_area.yview, orient='vertical')
    scrollbar.pack(side=tk.RIGHT, fill='y')
    scrollbar.grid(row=1, column=1, sticky="ns")

    text_area.configure(yscrollcommand=scrollbar.set)
    frame_buttons = tk.Frame(root, relief=tk.RAISED, bd=2)

    pause_sync_button = tk.Button(frame_buttons, text="Pause sync", width=15, height=4)
    pause_sync_button.grid(column=2, row=0, sticky="ew", padx=5, pady=5)
    pause_sync_button.bind('<Button-1>', toggle_pause_sync)

    # activity_button = tk.Button(frame_buttons, text="Activity", width=15, height=4)
    # activity_button.grid(column=3, row=0, sticky="ew", padx=5, pady=5)

    frame_buttons.grid(row=0, column=0, sticky="ns")
    text_area.grid(row=1, column=0, sticky='nwes')

def check_config(config):
    ok = True

    for k, v in config.items():
        if isinstance(v, dict):
            if not check_config(v):
                ok = False
        
        if v == '':
            ok = False
            debug("set {0} in config.json".format(k), False)

    return ok

# todo show gui message
if not os.path.exists('config.json'):
    msg = "Create configuration file config.json. Take a look at README for example."
    just_print(msg, False)

    sys.exit(0)

config = None
with open('config.json') as f:
    config = json.load(f)

if config['debug']:
    debug(json.dumps(config), False)

if not check_config(config):
    debug("Fix config.json.", False)
    sys.exit(0)

sync_pause = False

db = get_db()
s3 = boto3.client("s3",
    aws_access_key_id=config['remote']['access_key'],
    aws_secret_access_key=config['remote']['secret_key'],
    endpoint_url=config['remote']['host'],
)

root = tk.Tk()
root.title(config['title'])
root.rowconfigure(1, minsize=800, weight=1)
root.columnconfigure(0, minsize=800, weight=1)

window_width = 900
window_height = 900

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x_cordinate = int((screen_width / 2) - (window_width / 2))
y_cordinate = int((screen_height / 2) - (window_height / 2))

root.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))

img = ImageTk.PhotoImage(Image.open(config['logo']))
panel = tk.Label(root, image=img)
panel.pack(side="bottom", fill="both", expand="yes")

text_area = None
pause_sync_button = None

root.after(1000, clear_logo)
root.after(1010, main_gui)
root.after(1000 * config['sync_time'], sync)

root.mainloop()
if db:
    db.close()