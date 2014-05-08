import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)
ps = r.pubsub()

# analytics

def subscribe_channel(channel, callback):
	ps.subscribe(channel)
	for item in ps.listen():
		if item['type'] == 'message':
			callback(item['data'])

def publish_to_channel(channel, message):
	r.publish(channel, message)