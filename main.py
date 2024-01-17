from tkinter import *
from PIL import ImageTk, Image
import json
import os
import sqlite3, boto3
from sqlite3 import Error


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


def clear_logo():
    panel.pack_forget()


def get_remote_data():
    response = s3.list_objects(
        Bucket=config['remote']['bucket'],
        MaxKeys=1000000,
    )

    return response['Contents']


# todo: implement
def get_remote_version(key):
    return 1


def sync():
    global db

    if config['debug']:
        print("syncing after {0}s".format(config['sync_time']))

    sql = 'select count(*) as count from files'
    cursor = db.execute(sql)
    row = cursor.fetchone()
    if config['debug']:
        print("we have {0} files in local db".format(row['count']))

    if row['count'] == 0:
        objects = get_remote_data()
        for o in objects:
            if config['debug']:
                print(o)
            path = "{0}/{1}".format(config['remote']['bucket'], o['Key'])
            _type = "file"

            if o['Key'].endswith('/') and o['Size'] == 0:
                _type = "directory"

            version = {
                config['local_device_name']: 1,
                config['remote']['host']: get_remote_version(o['Key'])
            }

            sql = "insert into files(path, version, type, remote_etag) values (?, ?, ?, ?)"
            cursor = db.cursor()
            cursor.execute(sql, [path, json.dumps(version), _type, o['ETag'].replace('"', "")])
            db.commit()

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