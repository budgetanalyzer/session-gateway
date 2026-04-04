-- Conditionally updates hash fields and TTL only if the key exists.
-- KEYS[1]: session hash key
-- KEYS[2]: user sessions index key
-- ARGV[1]: session ID
-- ARGV[2..N-1]: field/value pairs to HSET
-- ARGV[N]: TTL in seconds (always the last argument)
-- Returns 1 if updated, 0 if session does not exist.
if redis.call('exists', KEYS[1]) == 1 then
  for i = 2, #ARGV - 1, 2 do
    redis.call('hset', KEYS[1], ARGV[i], ARGV[i + 1])
  end
  local ttl = tonumber(ARGV[#ARGV])
  redis.call('expire', KEYS[1], ttl)
  redis.call('sadd', KEYS[2], ARGV[1])
  redis.call('expire', KEYS[2], ttl)
  return 1
end
return 0
