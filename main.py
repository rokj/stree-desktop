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
is_root = lambda path: True if path == config['remote']['bucket'] else False

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


def get_remote_data(prefix=None, delimiter=None, remove_prefix=True):
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

# todo: implement
def get_remote_version(key, version=None):
    response = s3.get_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key
    )

    if response:
        found = ""
        for tag in response['TagSet']:
            if tag['Key'] == "s_version":
                found = tag['Value']
                break

        if found == "":
            found = set_remote_version(key)

            if not found:
                return None

        return found

    print("error getting tag s_version of an object {0} in bucket {1}".format(key, config['remote']['bucket']))

    return None


def set_remote_version(key):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    response = s3.put_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key,
        Tagging={
            "TagSet": [
                {
                    'Key': 's_version',
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    print("error setting tag s_version for an object {0} in bucket {1} and version".format(key, config['remote']['bucket'], now))

    return False


def get_remote_bucket_version():
    response = s3.get_bucket_tagging(
        Bucket=config['remote']['bucket'],
    )

    if response:
        found = ""
        for tag in response['TagSet']:
            if tag['Key'] == "s_version":
                found = tag['Value']
                break

        if found == "":
            found = set_remote_bucket_version()

            if not found:
                return None

        if config['debug']:
            print("remote bucket version {0}".format(found))

        return found

    print("error getting tag s_version of a bucket {0}".format(config['remote']['bucket']))

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
                    'Key': 's_version',
                    'Value': now
                }
            ]
        }
    )

    if response:
        return now

    print("error setting tag s_version for bucket {0}".format(config['remote']['bucket']))

    return None


def local_file_from_path(path):
    sql = 'select id from files where path = ?'
    cursor = db.cursor()
    result = cursor.execute(sql, [path])
    row = result.fetchone()
    return row

def download_remote_file(o):
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

    if not local_file_from_path(path):
        sql = "insert into files(path, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?)"
        cursor = db.cursor()
        cursor.execute(sql, (path, json.dumps(version), object_type(o), local_etag, remote_etag))
        db.commit()

def get_local_bucket_version():
    sql = "select value from info where key = 'bucket_version'"
    cursor = db.cursor()
    result = cursor.execute(sql)
    row = result.fetchone()

    if config['debug']:
        print("local bucket version {0}".format(row['value']))

    return row['value']

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
        return row['version']

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


def update_remote_parent_versions(path):
    if not path or path == "":
        return

    splitted_path = path.split("/")

    while len(splitted_path) > 0:
        if not path.endswith("/"):
            path = path + "/"

        if config['debug']:
            print("update version for path {0}".format(path))
            print("splitted_path: {0}".format(splitted_path))

        set_remote_version(path)

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)

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
            tmp_local_version = json.loads(local_version)
            if tmp_local_version[config['remote']['host']] != remote_version:
                tmp_local_version[config['remote']['host']] = remote_version
                sql = 'update files set version = ? where path = ?'
                cursor = db.cursor()
                cursor.execute(sql, [json.dumps(tmp_local_version), full_remote_path])
                db.commit()

        splitted_path = splitted_path[:-1]
        path = "/".join(splitted_path)


def sync():
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
        i = 0
        todo = get_remote_data(prefix="", delimiter="/")
        while i < len(todo):
            o = todo[i]
            i += 1

            if config['debug']:
                print(o)

            if object_type(o) == "directory":
                tmp = get_remote_data(prefix=o['Key'], delimiter="/")
                todo.extend(tmp)

            download_remote_file(o)

        bucket_version = get_remote_bucket_version()
        sql = "insert into info(key, value) values ('bucket_version', ?)"
        cursor = db.cursor()
        cursor.execute(sql, [(bucket_version)])
        db.commit()

    else:
        # todo
        # we are extra cautious if there are remote and local changes
        # first we check for remote changes
        remote_bucket_version = get_remote_bucket_version()
        if remote_bucket_version == "":
            if config['debug']:
                print("we should not be here, since remote bucket s_version tag should be set from previous actions")
                return

        local_bucket_version = get_local_bucket_version()
        if local_bucket_version == "":
            # todo
            if config['debug']:
                print("we should not be here, since local bucket s_version tag should be set from previous actions")
                return

        if local_bucket_version != remote_bucket_version:
            print("local bucket version differs from remote bucket version")
            print("local: {0} remote: {1}".format(local_bucket_version, remote_bucket_version))

            i = 0
            todo = get_remote_data(prefix="", delimiter="/")
            while i < len(todo):
                o = todo[i]
                i += 1

                if object_type(o) == "directory":
                    path = remote_path(o['Key'])
                    if config['debug']:
                        print("checking directory with path: {0}".format(path))
                    if not local_file_from_path(path):
                        if config['debug']:
                            print("directory with path: {0} not in db, we should add it".format(path))
                        check_remote_paths_for_its_existence(path_from_key(o['Key']))
                        download_remote_file(o)
                        update_local_parent_versions(path_from_key(o['Key']))

                        tmp = get_remote_data(prefix=o['Key'], delimiter="/")
                        todo.extend(tmp)
                # if remote does exist but local does not, get or create it
                if object_type(o) == "file":
                    path = remote_path(o['Key'])
                    if config['debug']:
                        print("checking object {0}".format(o))
                        print("checking file with path: {0}".format(path))
                    if not local_file_from_path(path):
                        if config['debug']:
                            print("file with path: {0} not in db, we should add it".format(path))
                        check_remote_paths_for_its_existence(path_from_key(o['Key']))
                        download_remote_file(o)
                        update_local_parent_versions(path_from_key(o['Key']))

            remote_bucket_version = get_remote_bucket_version()
            set_local_bucket_version(remote_bucket_version)
    if config['debug']:
        print("just before sync")
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

        sql = 'create table if not exists files(id integer primary key autoincrement, path varchar(255) unique, version varchar(255), type varchar(9), remote_etag varchar(32), local_etag varchar(32))'
        cursor.execute(sql)

        sql = 'create table if not exists info(key varchar(20) primary key, value varchar(50))'
        cursor.execute(sql)
    except Error as e:
        print(e)

    return conn


def add_tmp_file_click(event):
    print(s3.put_object(Body='/home/arne/tmp/testni-file3.txt', Bucket=config['remote']['bucket'],
                        Key='testni-file4.txt'))
    print(s3.put_object(Body='/home/arne/tmp/testni-file3.txt', Bucket=config['remote']['bucket'],
                        Key='tlenot/testni-file3.txt'))

    update_remote_parent_versions(path_from_key('testni-file4.txt'))
    update_remote_parent_versions(path_from_key('tlenot/testni-file3.txt'))

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
    frame.grid(row=2, column=1)

    add_tmp_file_button = tk.Button(frame, text="ADD", width=15, height=4)
    add_tmp_file_button.grid(column=0, row=0)
    add_tmp_file_button.bind('<Button-1>', add_tmp_file_click)

    pause_sync_button = tk.Button(frame, text="Pause sync", width=15, height=4)
    pause_sync_button.grid(column=1, row=0)
    pause_sync_button.bind('<Button-1>', toggle_pause_sync)

    activity_button = tk.Button(frame, text="Activity", width=15, height=4)
    activity_button.grid(column=2, row=0)

    text_area = tk.Text(frame, width=100, height=15, wrap="none")
    # ys = tk.Scrollbar(frame, orient='vertical', command=text_area.yview)
    # xs = tk.Scrollbar(frame, orient='horizontal', command=text_area.xview)
    # text_area['yscrollcommand'] = ys.set
    # text_area['xscrollcommand'] = xs.set
    text_area.insert('end', "Lorem ipsum...\n...\n...")
    text_area.grid(column=0, row=1, sticky='nwes', columnspan=3)
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