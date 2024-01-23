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
object_type = lambda o: "directory" if o['Key'].endswith('/') and o['Size'] == 0 else "file"
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


def on_top_path(path):
    tmp_split = path.split("/")
    if '' in tmp_split:
        tmp_split.remove('')

    if len(tmp_split):
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


def get_remote_data(prefix=None, delimiter=None):
    if delimiter and prefix:
        response = s3.list_objects(
            Bucket=config['remote']['bucket'],
            MaxKeys=config['remote']['max_keys'],
            Prefix=prefix,
            Delimiter=delimiter
        )
    else:
        response = s3.list_objects(
            Bucket=config['remote']['bucket'],
            MaxKeys=config['remote']['max_keys']
        )

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

        if config['debug']:
            print("remote bucket version {0}".format(found))
        return found

    print("error getting tag s_version of a bucket {0}".format(config['remote']['bucket']))

    return None


def set_bucket_version(now=None):
    if now is None:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

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
    cursor = db.execute(sql, [path])
    row = cursor.fetchone()
    return row

def download_remote_file(o):
    if config['debug']:
        print("about to download file from key {0}".format(o['Key']))

    remote_version = get_remote_version(o['Key'])
    if remote_version is None:
        print("could not get remote version")
        return

    version = {
        config['local_device_name']: remote_version,
        config['remote']['host']: remote_version
    }

    path = remote_path(o['Key'])
    if config['debug']:
        print("will download to {0}".format(path))
    remote_etag = o['ETag'].replace('"', "")
    local_etag = ""
    if object_type(o) == "file":
        s3.download_file(config['remote']['bucket'], o['Key'], path)
        local_etag = get_local_etag(pathlib.Path(path))

    if config['debug']:
        print("local etag {0}".format(local_etag))
        print("remote etag {0}".format(remote_etag))
        if local_etag != remote_etag:
            print("we should not be here. etags should be the same. got local etag {0} and remote etag {1}".format(local_etag, remote_etag))

    sql = "insert into files(path, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?)"
    cursor = db.cursor()
    cursor.execute(sql, [path, json.dumps(version), object_type(o), local_etag, remote_etag])
    db.commit()

def get_local_bucket_version():
    sql = 'select value from info where key = ?'
    cursor = db.execute(sql, ['bucket_version'])
    row = cursor.fetchone()
    if config['debug']:
        print("local bucket version {0}".format(row['value']))

    return row['value']


def get_local_version(path):
    sql = 'select version from files where path = ?'
    cursor = db.execute(sql, [path])
    row = cursor.fetchone()

    if row:
        return row['version']

    return None


def check_remote_paths_for_its_existence(path):
    max_checks = 40
    i = 0

    while True:
        path = path + "/"
        if config['debug']:
            print("checking path for its existence {0}".format(path))

        response = s3.head_object(
            Bucket=config['remote']['bucket'],
            Key=path)
        if not response:
            if config['debug']:
                print("no path object exists, so we create one")
            s3.put_object(Bucket=config['remote']['bucket'], Key=path, Body='')

        if on_top_path(path):
            break

        path = path.rpartition("/")[0]

        i += 1
        if i > max_checks:
            print("too deep path?")
            break

def update_parent_versions(path):
    while True:
        path = path + "/"
        if config['debug']:
            print("checking path for its existence {0}".format(path))

        full_remote_path = remote_path(path)

        remote_version = get_remote_version(path)
        local_version = get_local_version(full_remote_path)

        if local_version is not None:
            tmp_local_version = json.loads(local_version)
            if tmp_local_version[config['remote']['host']] != remote_version:
                tmp_local_version[config['remote']['host']] = remote_version
                sql = 'update files set version = ? where path = ?'
                db.execute(sql, [json.dumps(tmp_local_version), full_remote_path])

        if on_top_path(path):
            break

        path = path.rpartition("/")[0]


def sync():
    if sync_pause:
        root.after(1000 * config['sync_time'], sync)
        return

    global db

    if config['debug']:
        print("syncing after {0}s".format(config['sync_time']))

    sql = 'select count(*) as count from files'
    cursor = db.execute(sql)
    row = cursor.fetchone()
    if config['debug']:
        print("we have {0} files in local db".format(row['count']))

    # if this is first launch of the program, then we populate local db with remote "data"
    # we do not require "lock" for first usage
    if row['count'] == 0:
        objects = get_remote_data()
        for o in objects:
            if config['debug']:
                print(o)
            path = remote_path(o['Key'])

            remote_version = get_remote_version(o['Key'])
            if remote_version is None:
                continue

            if remote_version == "":
                remote_version = set_remote_version(o['Key'])

            version = {
                config['local_device_name']: remote_version,
                config['remote']['host']: remote_version
            }

            local_dir = os.path.dirname(path)

            if config['debug']:
                print('local path: {0}'.format(path))
                print('local dir: {0}'.format(local_dir))

            if not os.path.exists(local_dir):
                os.makedirs(local_dir)

            pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)

            remote_etag = o['ETag'].replace('"', "")
            local_etag = ""
            if object_type(o) == "file":
                s3.download_file(config['remote']['bucket'], o['Key'], path)
                local_etag = get_local_etag(pathlib.Path(path))

            sql = "insert into files(path, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?)"
            cursor = db.cursor()
            cursor.execute(sql, [path, json.dumps(version), object_type(o), local_etag, remote_etag])
            db.commit()

            if object_type(o) == "file" and config['debug'] and local_etag != remote_etag:
                print('local etag: {0}'.format(get_local_etag(pathlib.Path(path))))
                print('remote etag: {0}'.format(remote_etag))

        if len(objects) > 0:
            bucket_version = set_bucket_version()
            sql = "insert into info(key, value) values ('bucket_version', ?)"
            cursor = db.cursor()
            cursor.execute(sql, [bucket_version])
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

        versions_to_update = []
        check_again = False
        if local_bucket_version != remote_bucket_version:
            print("local bucket version differs from remote bucket version")
            print("local: {0} remote: {1}".format(local_bucket_version, remote_bucket_version))

            objects = get_remote_data(prefix="", delimiter="/")
            for o in objects:
                path = remote_path(o['Key'])
                # if remote does exist but local does not, get or create it
                if not local_file_from_path(path):
                    if config['debug']:
                        print("path: {0} is not in local db".format(path))
                    if object_type(o) == "file":
                        check_remote_paths_for_its_existence(path_from_key(o['Key']))
                        download_remote_file(o)
                        update_parent_versions(path_from_key(o['Key']))
                    if object_type(o) == "directory":
                        # todo: recurse to directory
                        pass

            remote_bucket_version = get_remote_bucket_version()
            set_bucket_version(remote_bucket_version)

        # now we check for local changes


    root.after(1000 * config['sync_time'], sync)


def get_db():
    conn = None
    try:
        conn = sqlite3.connect('stree.db')
        conn.row_factory = sqlite3.Row

        sql = 'drop table files'
        conn.execute(sql)

        sql = 'drop table info'
        conn.execute(sql)

        sql = 'create table if not exists files(id integer primary key autoincrement, path varchar(255) unique, version varchar(255), type varchar(9), remote_etag varchar(32), local_etag varchar(32))'
        conn.execute(sql)

        sql = 'create table if not exists info(key varchar(20) primary key, value varchar(50))'
        conn.execute(sql)
    except Error as e:
        print(e)

    return conn


def add_tmp_file_click(event):
    print(s3.put_object(Body='/home/arne/tmp/testni-file3.txt', Bucket=config['remote']['bucket'], Key='tlenot/testni-file3.txt'))
    set_bucket_version()


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

root.after(2400, clear_logo)
root.after(1000 * config['sync_time'], sync)
root.after(2500, main_gui)

root.mainloop()
if db:
    db.close()