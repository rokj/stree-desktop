import datetime
import tkinter as tk
from PIL import ImageTk, Image
import json
import os
import sqlite3, boto3
from sqlite3 import Error
import hashlib

import pathlib
from typing import Optional
import math
import re

print("watch out; we are deleting everything in /home/arne/development/python/stree/arnes-shramba/")
os.system("rm -rf /home/arne/development/python/stree/arnes-shramba/")

remote_path = lambda key: "{0}/{1}".format(config['remote']['bucket'], key)
skip_empty_objects = lambda o: True if o['Key'].endswith('/') and o['Size'] == 0 else False
path_from_key = lambda string: string.rpartition('/')[0]

config = None
with open('config.json') as f:
    config = json.load(f)

root = tk.Tk()
root.title(config['title'])
root.resizable(False, False)  # This code helps to disable windows from resizing

window_height = 500
window_width = 900

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x_cordinate = int((screen_width/2) - (window_width/2))
y_cordinate = int((screen_height/2) - (window_height/2))

root.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))

img = ImageTk.PhotoImage(Image.open(config['logo']))
panel = tk.Label(root, image=img)
panel.pack(side="bottom", fill="both", expand="yes")


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


def get_local_etag(path: pathlib.Path, chunk_size_bytes: Optional[int] = None) -> str:
    """Calculates an expected AWS s3 upload etag for a local on-disk file.
    Takes into account multipart uploads, but does NOT account for additional encryption
    (like KMS keys)
    """

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
    response = s3.list_objects(
        Bucket=config['remote']['bucket'],
        MaxKeys=config['remote']['max_keys'],
        Prefix=prefix,
        Delimiter=delimiter
    )

    if 'CommonPrefixes' in response:
        for cp in response['CommonPrefixes']:
            response['Contents'].append({
                'Key': cp['Prefix'],
                'IsDirectory': True
            })

    if remove_prefix:
        tmp = []
        for r in response['Contents']:
            if r['Key'] == prefix:
                continue
            tmp.append(r)

        return tmp

    return response['Contents']

def list_local_folders_in_db(path):
    path_depth = path.count("/")
    path_depth_plus_one = path_depth + 1
    path += "%"
    sql = 'select id, path, path_depth, version, local_etag, remote_etag, type from files where path like ? and (path_depth = ? or (path_depth = ? and type = "directory"))'
    cursor = db.cursor()
    result = cursor.execute(sql, [path, path_depth, path_depth_plus_one])
    row = result.fetchall()
    if config['debug']:
        print("getting row from path {0}: {1}".format(path, row))

    return row

def list_local_folders(path):
    entries = []

    for entry in os.scandir(path):
        tmp = {
            "absolute_path": entry.path,
            "Key": entry.path.replace(config['local_path'], ""), # this is actually relative path
            "type": "directory" if entry.is_dir() else "file"
        }
        entries.append(tmp)

    return entries

# todo: implement
def get_remote_version(key, version=None):
    response = s3.get_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key
    )

    if response:
        found = ""
        for tag in response['TagSet']:
            if tag['Key'] == "real_datetime_updated":
                found = tag['Value']
                break

        if found == "":
            found = set_remote_version(key)

        return found

    print("error getting tag real_datetime_updated of an object {0} in bucket {1}".format(key, config['remote']['bucket']))

    return None


def set_remote_version(key, now=None):
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

    response = s3.put_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key,
        Tagging={
            "TagSet": [
                {
                    'Key': 'real_datetime_updated',
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    print("error setting tag real_datetime_updated for an object {0} in bucket {1} and version".format(key, config['remote']['bucket'], now))

    return None


def get_remote_bucket_version():
    response = s3.get_bucket_tagging(
        Bucket=config['remote']['bucket'],
    )

    if response:
        found = ""
        for tag in response['TagSet']:
            if tag['Key'] == "real_datetime_updated":
                found = tag['Value']
                break

        if found == "":
            found = set_remote_bucket_version()

            if not found:
                return None

        if config['debug']:
            print("remote bucket version {0}".format(found))

        return found

    print("error getting tag real_datetime_updated of a bucket {0}".format(config['remote']['bucket']))

    return None


def set_remote_bucket_version(now=None):
    if now is None:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    if config['debug']:
        print("setting {0} bucket version to {1}".format(config['remote']['bucket'], now))

    response = s3.put_bucket_tagging(
        Bucket=config['remote']['bucket'],
        Tagging={
            "TagSet": [
                {
                    'Key': 'real_datetime_updated',
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    print("error setting tag real_datetime_updated for bucket {0}".format(config['remote']['bucket']))

    return None


def file_from_db(path):
    sql = 'select id, path from files where path = ?'
    cursor = db.cursor()
    result = cursor.execute(sql, [path])
    row = result.fetchone()
    if config['debug']:
        print("getting row from path {0}: {1}".format(path, row))
    return row

def download_remote_file(o, delete_existing=True):
    key = o['Key']

    if config['debug']:
        print("about to download file/directory from key {0}".format(key))

    remote_version = get_remote_version(key)
    if remote_version is None:
        print("could not get remote version")
        return

    version = {
        config['local_device_name']: remote_version,
        config['remote']['host']: remote_version
    }

    path = remote_path(key)
    if config['debug']:
        print("will download to {0}".format(path))

    remote_etag = ""
    local_etag = ""
    path_depth = path.count("/")

    if object_type(o) == "file":
        # this is file, so we should download it
        if config['debug']:
            print("this is file, so we are doing actual download")
        remote_etag = o['ETag'].replace('"', "")
        # we create local dir if it not exists
        local_dir = os.path.dirname(path)
        if not os.path.exists(local_dir):
            if config['debug']:
                print("creating directory {0} for file {1}".format(local_dir, path))
            os.makedirs(local_dir)

        if delete_existing and os.path.isfile(path):
            if config['debug']:
                print("we are deleting file {0} so we can download it afterwards")
            os.remove(path)

        if not skip_empty_objects(o):
            s3.download_file(config['remote']['bucket'], key, path)
            local_etag = get_local_etag(pathlib.Path(path))
    else:
        if config['debug']:
            print("this is directory")
        if not os.path.exists(path):
            if config['debug']:
                print("creating directory {0}".format(path))
            os.makedirs(path)

    if config['debug']:
        print("local etag {0}".format(local_etag))
        print("remote etag {0}".format(remote_etag))
        if object_type(o) == "file" and local_etag != remote_etag:
            print("we should not be here. etags should be the same. got local etag and remote etag")
        print("type {0}".format(object_type(o)))

    if file_from_db(path) is None:
        sql = "insert into files(path, path_depth, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (path, path_depth, json.dumps(version), object_type(o), local_etag, remote_etag))
        db.commit()
    else:
        sql = "update files set version = ?, local_etag = ?, remote_etag = ? where path = ?"
        cursor = db.cursor()
        cursor.execute(sql, (json.dumps(version), local_etag, remote_etag, path))
        db.commit()


def get_remote_etag(key):
    response = s3.list_objects(
        Bucket=config['remote']['bucket'],
        Key=key,
    )
    if response:
        return response['ETag']

    return None


def remote_key_exists(key):
    print("checking if remote key {0} exists".format(key))

    try:
        s3.head_object(Bucket=config['remote']['bucket'], Key=key)
    except boto3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False

        print("we should not be here")

    return True


def upload_local_file(o, delete_existing=False):
    key = o['Key']

    if config['debug']:
        print("about to upload file/directory {0} to key {1}".format(o['absolute_path'], key))

    remote_etag = ""
    local_etag = ""

    remote_version = ""
    version = {
        config['local_device_name']: get_local_version(remote_path(key)),
        config['remote']['host']: remote_version
    }

    if o["type"] == "file":
        # this is file, so we should upload it
        if config['debug']:
            print("this is file, so we are doing actual upload")

        s3.upload_file(o['absolute_path'], config['remote']['bucket'], key)
        version[config['remote']['host']] = set_remote_version(key)
        local_etag = get_local_etag(pathlib.Path(o['absolute_path']))
        remote_etag = get_remote_etag(key)

    else:
        if config['debug']:
            print("this is directory")
            # todo

    if config['debug']:
        print("local etag {0}".format(local_etag))
        print("remote etag {0}".format(remote_etag))
        if o['type'] == "file" and local_etag != remote_etag:
            print("we should not be here. etags should be the same. got local etag and remote etag")
        print("type {0}".format(o['type']))

    if file_from_db(key) is None:
        path_depth = key.count("/")

        sql = "insert into files(path, path_depth, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (key, path_depth, json.dumps(version), o['type'], local_etag, remote_etag))
        db.commit()
    else:
        sql = "update files set version = ?, local_etag = ?, remote_etag = ? where path = ?"
        cursor = db.cursor()
        cursor.execute(sql, (json.dumps(version), local_etag, remote_etag, key))
        db.commit()

def get_local_bucket_version():
    sql = "select version from files where path = ?"
    cursor = db.cursor()
    result = cursor.execute(sql, (config['remote']['bucket'] + "/"))
    row = result.fetchone()

    if config['debug']:
        print("local bucket version {0}".format(row['value']))

    return json.loads(row['version'])

def set_local_bucket_version(version):
    sql = "update info set value = ? where key = 'bucket_version'"
    cursor = db.cursor()
    cursor.execute(sql, [(version)])
    db.commit()


def get_local_version(path):
    sql = 'select version from files where path = ?'
    cursor = db.cursor()
    result = cursor.execute(sql, [(path)])
    row = result.fetchone()

    if row:
        version = json.loads(row['version'])
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

        if config['local_device_name'] not in version:
            version['local_device_name'] = now
            sql = 'update files set version = ? where path = ?'
            cursor = db.cursor()
            cursor.execute(sql, [json.dumps(version), path])
            db.commit()


        return version

    return None


def check_remote_paths_for_its_existence(path):
    if not path or path == "":
        return

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        if not path.endswith("/"):
            path = path + "/"

        if config['debug']:
            print("checking path for its existence {0}".format(path))
            print("splitted_path: {0}".format(splitted_path))

        response = s3.head_object(
            Bucket=config['remote']['bucket'],
            Key=path)
        if not response:
            if config['debug']:
                print("no path object exists, so we create one")
            s3.put_object(Bucket=config['remote']['bucket'], Key=path, Body='')

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)


# todo update versions with now parameter if set
def update_remote_parent_versions(path, same_real_datetime_update=False):
    if not path or path == "":
        return

    now = None
    if same_real_datetime_update:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        if not path.endswith("/"):
            path = path + "/"

        if config['debug']:
            print("update version for path {0}".format(path))
            print("splitted_path: {0}".format(splitted_path))

        set_remote_version(path, now)

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

    set_remote_bucket_version(now)

# but watch out, if for some reason remote version does not exist, we create it
def update_local_parent_versions(path):
    if not path or path == "":
        return

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        if not path.endswith("/"):
            path = path + "/"

        if config['debug']:
            print("checking path for its existence {0}".format(path))
            print("splitted_path: {0}".format(splitted_path))

        full_remote_path = remote_path(path)
        remote_version = get_remote_version(path)
        local_version = get_local_version(full_remote_path)

        if local_version is not None:
            if local_version[config['remote']['host']] != remote_version:
                local_version[config['remote']['host']] = remote_version
                sql = 'update files set version = ? where path = ?'
                cursor = db.cursor()
                cursor.execute(sql, [json.dumps(local_version), full_remote_path])
                db.commit()

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

    remote_bucket_version = get_remote_bucket_version()
    local_bucket_version = get_local_bucket_version()

    if local_bucket_version is not None:
        if local_bucket_version[config['remote']['host']] != remote_bucket_version:
            local_bucket_version[config['remote']['host']] = remote_bucket_version
            sql = 'update files set version = ? where path = ?'
            cursor = db.cursor()
            cursor.execute(sql, [json.dumps(local_bucket_version), config['remote']['bucket']])
            db.commit()


def utc_to_float(utc_string):
    return datetime.datetime.strptime(utc_string, "%Y-%m-%d %H:%M:%S.%f").timestamp()

def check_bucket_changes():
    _remote_version = get_remote_bucket_version()
    _local_version = get_local_bucket_version()

    if _remote_version is None:
        print("could not get remote bucket version for bucket {0}".format(config['remote']['bucket']))
        return None

    if _local_version is None:
        print("could not get local bucket version for bucket {0}".format(config['remote']['bucket']))
        return None

    local_version_device = utc_to_float(_local_version[config['local_device_name']])
    local_version_remote = utc_to_float(_local_version[config['remote']['host']])
    remote_version = utc_to_float(_remote_version)

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

    _remote_version = get_remote_version(o['Key'])
    _local_version = get_local_version(path)

    if _remote_version is None or _local_version is None:
        print("could not get remote version for key {0} or local version {1}".format(o['Key'], path))
        return None

    local_version_device = utc_to_float(_local_version[config['local_device_name']])
    local_version_remote = utc_to_float(_local_version[config['remote']['host']])
    remote_version = utc_to_float(_remote_version)

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

def sync_from_remote():
    # todo check for deleted objects
    print("--- start checking remote ---")
    i = 0
    remote_todo = list_remote_objects(prefix="", delimiter="/")
    while i < len(remote_todo):
        o = remote_todo[i]
        i += 1

        if object_type(o) == "directory":
            path = remote_path(o['Key'])
            if config['debug']:
                print("checking remote directory with path: {0}".format(path))
            if file_from_db(path) is None:
                if config['debug']:
                    print("remote directory with path: {0} not in local db, we should add it".format(path))
                check_remote_paths_for_its_existence(path_from_key(o['Key']))
                # we just do insert into db, but do not download anything (done in download_remote_file function)
                download_remote_file(o)

                tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                remote_todo.extend(tmp)
            else:
                # if remote version differs from local version, we add it to todo list
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    print("CONFLICT: key {0} of path {1} changed locally and remotely".format(o['Key'], path))
                    continue

                if changed["locally"] or changed["remotely"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                    remote_todo.extend(tmp)

        # if remote does exist but local does not, get or create it
        if object_type(o) == "file":
            path = remote_path(o['Key'])

            if config['debug']:
                print("checking remote object {0}".format(o))
                print("checking file with path: {0}".format(path))

            if file_from_db(path) is None:
                # 1. check if there was a new file added
                if config['debug']:
                    print("local file with path: {0} not in db, we should add it".format(path))
                check_remote_paths_for_its_existence(path_from_key(o['Key']))
                download_remote_file(o)
                update_local_parent_versions(path_from_key(o['Key']))
            else:
                # 2. check if file was updated
                # if remote version differs from local version, we update it
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    print("CONFLICT: key {0} of path {1} changed locally and remotely".format(o['Key'], path))
                    continue

                if changed["locally"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    tmp = {
                        "absolute_path": config['local_path'] + path,
                        "Key": path,
                        "type": "file"
                    }
                    upload_local_file(tmp)
                    update_remote_parent_versions(path_from_key(o['Key']))

                if changed["remotely"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    download_remote_file(o)
                    update_local_parent_versions(path_from_key(o['Key']))
    print("--- end checking remote ---")

def sync_to_remote():
    print("--- start checking local ---")
    i = 0
    local_todo = list_local_folders(config['local_path'])
    while i < len(local_todo):
        o = local_todo[i]
        i += 1

        if o["type"] == "directory":
            if config['debug']:
                print("checking local directory with path: {0}".format(o["absolute_path"]))
            if file_from_db(o["Key"]) is None:
                if config['debug']:
                    print("directory with path: {0} not in db, we should add it".format(o["absolute_path"]))
                check_remote_paths_for_its_existence(path_from_key(o["Key"]))
                # we just do insert into db, but do not upload anything (done in upload_local_file function)
                upload_local_file(o)

                tmp = list_local_folders(o["absolute_path"])
                local_todo.extend(tmp)
            else:
                # if remote version differs from local version, we add it to todo list
                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    print("CONFLICT: key {0} changed locally and remotely".format(o['Key']))
                    continue

                if changed["locally"] or changed["remotely"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    tmp = list_local_folders(o["absolute_path"])
                    local_todo.extend(tmp)
        else:
            if config['debug']:
                print("checking remote object {0}".format(o))

            if file_from_db(o['Key']) is None:
                # 1. check if there was a new file added
                if config['debug']:
                    print("local file with path: {0} not in db, we should add it".format(o['absolute_path']))

                # add_to_db(o['Key'])

                check_remote_paths_for_its_existence(path_from_key(o['Key']))
                if remote_key_exists(o['Key']):
                    print(
                        "CONFLICT: we try to add local file to remote, but remote file with key {0} already exists".format(
                            o['Key']))
                    continue
                upload_local_file(o)
                update_remote_parent_versions(path_from_key(o['Key']), True)
            else:
                # 2. check if file was updated
                # if remote version differs from local version, we update it

                changed = check_object_changes(o)
                if changed is None:
                    continue

                if changed["locally"] and changed["remotely"]:
                    print("CONFLICT: key {0} changed locally and remotely".format(o['Key']))
                    continue

                if changed["locally"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    tmp = {
                        "absolute_path": config['local_path'] + o['Key'],
                        "Key": o['Key'],
                        "type": "file"
                    }
                    upload_local_file(tmp)
                    update_remote_parent_versions(path_from_key(o['Key']), True)

                if changed["remotely"]:
                    check_remote_paths_for_its_existence(path_from_key(o['Key']))
                    download_remote_file(o)
                    update_local_parent_versions(path_from_key(o['Key']))
    print("--- end checking local ---")

def sync():
    if config['debug']:
        print("just before sync")

    if sync_pause:
        root.after(1000 * config['sync_time'], sync)
        return

    global db

    if config['debug']:
        print("syncing after {0}s".format(config['sync_time']))

    sql = 'select count(*) as count from files'
    cursor = db.cursor()
    result = cursor.execute(sql)
    row = result.fetchone()
    if config['debug']:
        print("we have {0} files in local db".format(row['count']))

    # if this is first launch of the program, then we populate local db with remote "data"
    # we do not require "lock" for first usage
    if row['count'] == 0:
        local_entries = os.scandir(config['local_path'])
        if len(local_entries) > 0:
            print("local path should be empty on first run")
            return

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

            if config['debug']:
                print(o)

            if object_type(o) == "directory":
                tmp = list_remote_objects(prefix=o['Key'], delimiter="/")
                remote_todo.extend(tmp)

            check_remote_paths_for_its_existence(path_from_key(o['Key']))
            download_remote_file(o)
            update_local_parent_versions(path_from_key(o['Key']))

        root.after(1000 * config['sync_time'], sync)

        return

    changed_bucket = check_bucket_changes()
    if changed_bucket["remotely"] == "":
        # todo show message to user
        if config['debug']:
            print("we should not be here, since remote bucket real_datetime_updated tag should be set from previous actions")
            return

    if changed_bucket["locally"] == "":
        # todo show message to user
        if config['debug']:
            print("we should not be here, since local bucket real_datetime_updated tag should be set from previous actions")
            return

    if changed_bucket["locally"] and changed_bucket["remotely"]:
        print("local AND remote files has been changed, this is possible CONFLICT, however let us try to sync anyway")

    elif changed_bucket["remotely"]:
        sync_from_remote()

    # todo: until we implement some watcher of changed files, we do full local scan every time
    # https://github.com/gorakhargosh/watchdog/
    sync_to_remote()

    root.after(1000 * config['sync_time'], sync)


def get_db():
    conn = None
    try:
        conn = sqlite3.connect('stree.db')
        conn.row_factory = sqlite3.Row

        sql = 'drop table files'
        cursor = conn.cursor()
        cursor.execute(sql)

        sql = 'drop table info'
        cursor.execute(sql)

        sql = 'create table if not exists files(id integer primary key autoincrement, path varchar(255) unique, path_depth integer, version varchar(255), type varchar(9), remote_etag varchar(32), local_etag varchar(32))'
        cursor.execute(sql)

        sql = 'create table if not exists info(key varchar(20) primary key, value varchar(50))'
        cursor.execute(sql)
    except Error as e:
        print(e)

    return conn


def add_tmp_file_click(event):
    # print(s3.upload_file('/home/arne/tmp/testni-file3.txt', config['remote']['bucket'], 'testni-file4.txt'))
    print(s3.put_object(Body='FAFAFA', Bucket=config['remote']['bucket'], Key='tlenot/testni-file3.txt'))

    set_remote_version('tlenot/testni-file3.txt')
    update_remote_parent_versions(path_from_key('tlenot/testni-file3.txt'))
    set_remote_bucket_version()

    # update_remote_parent_versions(path_from_key('tlenot/testni-file3.txt'))

def update_versions(event):
    sql = 'select path from files'
    cursor = db.cursor()
    result = cursor.execute(sql)
    rows = result.fetchall()
    for row in rows:
        print(row['path'])
        path = row['path'].replace("arnes-shramba/", "")
        set_remote_version(path)

    set_remote_bucket_version()


def toggle_pause_sync(event):
    global sync_pause

    if sync_pause:
        sync_pause = False
        if config['debug']:
            print("unpausing sync")
    else:
        sync_pause = True
        if config['debug']:
            print("pausing sync")

def main_gui():
    frame = tk.Frame(
        master=root,
        relief=tk.RAISED,
        borderwidth=1
    )
    frame.grid(row=2, column=4)

    add_tmp_file_button = tk.Button(frame, text="ADD", width=15, height=4)
    add_tmp_file_button.grid(column=0, row=0)
    add_tmp_file_button.bind('<Button-1>', add_tmp_file_click)

    update_versions_button = tk.Button(frame, text="UPDATE VERSIONS", width=15, height=4)
    update_versions_button.grid(column=1, row=0)
    update_versions_button.bind('<Button-1>', update_versions)

    pause_sync_button = tk.Button(frame, text="Pause sync", width=15, height=4)
    pause_sync_button.grid(column=2, row=0)
    pause_sync_button.bind('<Button-1>', toggle_pause_sync)

    activity_button = tk.Button(frame, text="Activity", width=15, height=4)
    activity_button.grid(column=3, row=0)

    text_area = tk.Text(frame, width=100, height=15, wrap="none")
    # ys = tk.Scrollbar(frame, orient='vertical', command=text_area.yview)
    # xs = tk.Scrollbar(frame, orient='horizontal', command=text_area.xview)
    # text_area['yscrollcommand'] = ys.set
    # text_area['xscrollcommand'] = xs.set
    text_area.insert('end', "Lorem ipsum...\n...\n...")
    text_area.grid(column=0, row=1, sticky='nwes', columnspan=4)
    # xs.grid(column=0, row=1, sticky='we')
    # ys.grid(column=1, row=0, sticky='ns')
    # frame.grid_columnconfigure(0, weight=1)
    # frame.grid_rowconfigure(0, weight=1)


sync_pause = False

db = get_db()
s3 = boto3.client("s3",
    aws_access_key_id=config['remote']['access_key'],
    aws_secret_access_key=config['remote']['secret_key'],
    endpoint_url=config['remote']['host'],
)

print("TODO DELETE THIS")
print(s3.delete_object(Bucket=config['remote']['bucket'], Key='tlenot/testni-file3.txt'))
print(s3.delete_object(Bucket=config['remote']['bucket'], Key='testni-file4.txt'))

root.after(2400, clear_logo)
root.after(1000 * config['sync_time'], sync)
root.after(2500, main_gui)

root.mainloop()
if db:
    db.close()