# Move all template files from project root to backend/templates/
import shutil
import os

src_dir = '../templates/'
dst_dir = './templates/'

for filename in os.listdir(src_dir):
    shutil.move(os.path.join(src_dir, filename), os.path.join(dst_dir, filename))
