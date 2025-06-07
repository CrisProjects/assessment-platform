# Move all static files from project root to backend/static/
import shutil
import os

src_dir = '../static/'
dst_dir = './static/'

for filename in os.listdir(src_dir):
    shutil.move(os.path.join(src_dir, filename), os.path.join(dst_dir, filename))
