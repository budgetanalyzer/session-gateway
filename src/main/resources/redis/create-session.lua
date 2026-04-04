-- Atomically creates a session hash and indexes it in the per-user session set.
-- KEYS[1]: session hash key
-- KEYS[2]: user sessions index key
-- ARGV[1]: session ID
-- ARGV[2]: TTL in seconds
-- ARGV[3..N]: alternating hash field/value pairs
-- Returns 1 on success.
for i = 3, #ARGV, 2 do
  redis.call('hset', KEYS[1], ARGV[i], ARGV[i + 1])
end

local ttl = tonumber(ARGV[2])
redis.call('expire', KEYS[1], ttl)
redis.call('sadd', KEYS[2], ARGV[1])
redis.call('expire', KEYS[2], ttl)

return 1
