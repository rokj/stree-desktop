from tkinter import *
from PIL import ImageTk, Image
import json
import os
import sqlite3, boto3
from sqlite3 import Error
import hashlib

import pathlib
from typing import Optional
import math


config = None
with open('config.json') as f:
    config = json.load(f)

root = Tk()
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
panel = Label(root, image=img)
panel.pack(side="bottom", fill="both", expand="yes")


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


def get_remote_data():
    response = s3.list_objects(
        Bucket=config['remote']['bucket'],
        MaxKeys=1000000,
    )

    return response['Contents']


# todo: implement
def get_remote_version(key, version=None):
    response = s3.get_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key
    )

    if response:
        found = 0
        for tag in response['TagSet']:
            if tag['Key'] == "s_version":
                found = tag['Value']
                break

        return found

    print("error getting tag of an object {0} in bucket {1}".format(key, config['remote']['bucket']))

    return None


def set_remote_version(key, version):
    response = s3.put_object_tagging(
        Bucket=config['remote']['bucket'],
        Key=key,
        Tagging={
            "TagSet": [
                {
                    'Key': 's_version',
                    'Value': str(version)
                }
            ]
        }
    )

    if response:
        return True

    print("error setting tag for an object {0} in bucket {1} and version".format(key, config['remote']['bucket'], version))

    return False


def sync():
    global db

    if config['debug']:
        print("syncing after {0}s".format(config['sync_time']))

    sql = 'select count(*) as count from files'
    cursor = db.execute(sql)
    row = cursor.fetchone()
    if config['debug']:
        print("we have {0} files in local db".format(row['count']))

    # if this is first launch of the program, then we populate local db with remote "data"
    if row['count'] == 0:
        objects = get_remote_data()
        for o in objects:
            if config['debug']:
                print(o)
            path = "{0}/{1}".format(config['remote']['bucket'], o['Key'])
            _type = "file"

            if o['Key'].endswith('/') and o['Size'] == 0:
                _type = "directory"

            remote_version = get_remote_version(o['Key'])
            if remote_version is None:
                continue

            if remote_version == 0:
                set_remote_version(o['Key'], 1)
                remote_version = 1

            version = {
                config['local_device_name']: 1,
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
            if _type == "file":
                s3.download_file(config['remote']['bucket'], o['Key'], path)
                local_etag = get_local_etag(pathlib.Path(path))

            sql = "insert into files(path, version, type, local_etag, remote_etag) values (?, ?, ?, ?, ?)"
            cursor = db.cursor()
            cursor.execute(sql, [path, json.dumps(version), _type, local_etag, remote_etag])
            db.commit()

            if _type == "file" and config['debug'] and local_etag != remote_etag:
                print('local etag: {0}'.format(get_local_etag(pathlib.Path(path))))
                print('remote etag: {0}'.format(remote_etag))
    else:
        # first we check for remote changes
        bucket_version = get_bucket_version()
        if bucket_version == 0:
            set_bucket_version(1)
            bucket_version = 1

        sql = 'select value from info where key = ?'
        cursor = db.execute(sql, 'bucket_version')
        row = cursor.fetchone()
        if config['debug']:
            print("local bucket version".format(row['value']))

        # now we check for local changes



    # root.after(1000 * config['sync_time'], sync)


def get_db():
    conn = None
    try:
        conn = sqlite3.connect('stree.db')
        conn.row_factory = sqlite3.Row

        sql = 'create table if not exists files(id integer primary key autoincrement, path varchar(255) unique, version varchar(255), type varchar(9), remote_etag varchar(32), local_etag varchar(32))'
        conn.execute(sql)

        sql = 'create table if not exists info(key varchar(20) primary key, value varchar(50))'
        conn.execute(sql)
    except Error as e:
        print(e)

    return conn


db = get_db()
s3 = boto3.client("s3",
    aws_access_key_id=config['remote']['access_key'],
    aws_secret_access_key=config['remote']['secret_key'],
    endpoint_url=config['remote']['host'],
)

root.after(2400, clear_logo)
root.after(1000 * config['sync_time'], sync)

root.mainloop()
if db:
    db.close()