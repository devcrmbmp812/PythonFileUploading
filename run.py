#!/usr/bin/python

from webapp import app

if __name__ == "__main__":
	app.run(port=5000,threaded=True,host='0.0.0.0',debug=True)
