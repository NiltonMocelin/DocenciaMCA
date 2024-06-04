    #!/usr/bin/env python
from flask import Flask, render_template, Response
import cv2
import sys
import numpy

# pip3 install flask
##$ pip3 install numpy
#$ pip3 install opencv-contrib-python
#$ pip3 install imutils

app = Flask(__name__)

def get_frame1():
    camera_port=0
    camera=cv2.VideoCapture(camera_port) #this makes a web cam object

    while True:
        retval, im = camera.read()
        imgencode=cv2.imencode('.jpg',im)[1]
        stringData=imgencode.tostring()
        yield (b'--frame\r\n'
            b'Content-Type: text/plain\r\n\r\n'+stringData+b'\r\n')

    del(camera)

def get_frame():
    video_capture = cv2.VideoCapture('video.mp4')
    
    while True:
        retval, im = video_capture.read()
        (flag,imgencode)=cv2.imencode('.jpg',im)

        if not flag:
            continue
        # stringData=imgencode.tostring()
        # yield (b'--frame\r\n'
        #     b'Content-Type: text/plain\r\n\r\n'+stringData+b'\r\n')
        yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + 
			bytearray(imgencode) + b'\r\n')

    del(vidcap)

@app.route('/vid')
def vid():
     return Response(get_frame(),mimetype='multipart/x-mixed-replace; boundary=frame')


if __name__ == '__main__':
    app.run(host='10.0.0.9',port=5000, debug=True, threaded=True)