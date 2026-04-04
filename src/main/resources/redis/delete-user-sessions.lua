-- Atomically deletes every indexed session for a user and the user session index key itself.
-- KEYS[1]: user sessions index key
-- ARGV[1]: session key prefix
-- Returns the number of deleted keys.
local sessionIds = redis.call('smembers', KEYS[1])
local keysToDelete = {}

for i = 1, #sessionIds do
  keysToDelete[#keysToDelete + 1] = ARGV[1] .. sessionIds[i]
end

keysToDelete[#keysToDelete + 1] = KEYS[1]

return redis.call('del', unpack(keysToDelete))
