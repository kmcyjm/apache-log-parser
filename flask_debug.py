from flask import Flask
from random import randint

app = Flask(__name__)

def highest_random(limit):
	highest = 0
	for i in range(5):
		r = randint(0, limit)
		if r > highest:
			highest = r

	msg = 'Hello {num:d}'.format(num=highest)

	return msg

@app.route('/')
def hello_world():
	upper_limit = 100
	msg = highest_random(upper_limit)
	return msg


if __name__ == '__main__':
	app.run(debug=True)