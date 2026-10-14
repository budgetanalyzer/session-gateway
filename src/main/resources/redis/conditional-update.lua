-- Conditionally updates hash fields and TTL only if the key exists.
-- KEYS[1]: session hash key
-- KEYS[2]: user sessions index key
-- ARGV[1]: session ID
-- ARGV[2..N-1]: field/value pairs to HSET
-- ARGV[N]: TTL in seconds (always the last argument)
-- Returns 1 if updated, 0 if session does not exist.
local session_type = redis.call('type', KEYS[1]).ok
if session_type == 'none' then
  return 0
end
if session_type ~= 'hash' then
  return redis.error_reply('session key is not a hash')
end

local index_type = redis.call('type', KEYS[2]).ok
if index_type ~= 'none' and index_type ~= 'set' then
  return redis.error_reply('user session index key is not a set')
end

local ttl = tonumber(ARGV[#ARGV])
redis.call('sadd', KEYS[2], ARGV[1])
for i = 2, #ARGV - 1, 2 do
  redis.call('hset', KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call('expire', KEYS[1], ttl)
redis.call('expire', KEYS[2], ttl)
return 1
