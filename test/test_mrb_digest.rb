assert("Digest::Base.new") do
  assert_raise(NotImplementedError, "Digest::Base is an abstract class") do
    Digest::Base.new
  end
end

assert("Digest::XXXX.block_size") do
  [
    ["MD5",    64],
    ["RMD160", 64],
    ["SHA1",   64],
    ["SHA256", 64],
    ["SHA384", 128],
    ["SHA512", 128],
  ].each do |data|
    d = Module.const_get("Digest").const_get(data[0]).new
    d.block_length data[1]
  end
end

assert("Digest::XXXX.reset") do
  [
    ["MD5",    "c4ca4238a0b923820dcc509a6f75849b"],
    ["RMD160", "c47907abd2a80492ca9388b05c0e382518ff3960"],
    ["SHA1",   "356a192b7913b04c54574d18c28d46e6395428ab"],
    ["SHA256", "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"],
    ["SHA384", "47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776"],
    ["SHA512", "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"],
  ].each do |data|
    d = Module.const_get("Digest").const_get(data[0]).new
    d.update "aaa"
    d.update "bbb"
    d.update "ccc"
    d.reset
    d.update "1"
    assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, data[1]
  end
end

assert("Digest::XXXX.digest") do
  [
    ["MD5",    "c4ca4238a0b923820dcc509a6f75849b"],
    ["RMD160", "c47907abd2a80492ca9388b05c0e382518ff3960"],
    ["SHA1",   "356a192b7913b04c54574d18c28d46e6395428ab"],
    ["SHA256", "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"],
    ["SHA384", "47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776"],
    ["SHA512", "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"],
  ].each do |data|
    d = Module.const_get("Digest").const_get(data[0]).new
    d.update "1"
    assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, data[1]
  end
end

assert("Digest::XXXX.digest_size") do
  [
    ["MD5",    16],
    ["RMD160", 20],
    ["SHA1",   20],
    ["SHA256", 32],
    ["SHA384", 48],
    ["SHA512", 64],
  ].each do |data|
    d = Module.const_get("Digest").const_get(data[0]).new
    d.digest_length data[1]
  end
end

assert("Digest::XXXX.hexdigest") do
  [
    ["MD5",    "c4ca4238a0b923820dcc509a6f75849b"],
    ["RMD160", "c47907abd2a80492ca9388b05c0e382518ff3960"],
    ["SHA1",   "356a192b7913b04c54574d18c28d46e6395428ab"],
    ["SHA256", "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"],
    ["SHA384", "47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776"],
    ["SHA512", "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"],
  ].each do |data|
    d = Module.const_get("Digest").const_get(data[0]).new
    d.update "1"
    assert_equal d.hexdigest, data[1]
  end
end

assert("Digest::HMAC.block_size") do
  [
    [Digest::MD5,    64],
    [Digest::RMD160, 64],
    [Digest::SHA1,   64],
    [Digest::SHA256, 64],
    [Digest::SHA384, 128],
    [Digest::SHA512, 128],
  ].each do |data|
    assert_equal Digest::HMAC.new("1", data[0]).block_length, data[1]
  end
end

assert("Digest::HMAC.digest") do
  [
    ["MD5",    "4af35dc1cd7f387546377a4f2b548d0c"],
    ["RMD160", "021940a1b424487cd2cb697688b56942e411b39c"],
    ["SHA1",   "e23feb105f9622241bf23db1638cd2b4208b1f53"],
    ["SHA256", "6da91fb91517be1f5cdcf3af91d7d40c717dd638a306157606fb2e584f7ae926"],
    ["SHA384", "5808b3b36a082f6f66a90c926dbafeb834157330614bf8b55c1f635a85b180454a70064de7c4f5d27ce1dd1d811d1407"],
    ["SHA512", "54816905e95d0a740369d5fb40cc37ce13761d9f56e897508590faf2306152093147409290592b6aeddc694b2de4a816526be399e7bf50a971a1537df831ca4a"],
  ].each do |data|
    h = Digest::HMAC.new "key", Module.const_get("Digest").const_get(data[0])
    h.update "1"
    assert_equal h.digest.bytes.map{|c| "%02x" % c}.join, data[1]
  end
end

assert("Digest::HMAC.digest_size") do
  [
    [Digest::MD5,    16],
    [Digest::RMD160, 20],
    [Digest::SHA1,   20],
    [Digest::SHA256, 32],
    [Digest::SHA384, 48],
    [Digest::SHA512, 64],
  ].each do |data|
    assert_equal Digest::HMAC.new("1", data[0]).digest_length, data[1]
  end
end

assert("Digest::HMAC.hexdigest") do
  [
    ["MD5",    "4af35dc1cd7f387546377a4f2b548d0c"],
    ["RMD160", "021940a1b424487cd2cb697688b56942e411b39c"],
    ["SHA1",   "e23feb105f9622241bf23db1638cd2b4208b1f53"],
    ["SHA256", "6da91fb91517be1f5cdcf3af91d7d40c717dd638a306157606fb2e584f7ae926"],
    ["SHA384", "5808b3b36a082f6f66a90c926dbafeb834157330614bf8b55c1f635a85b180454a70064de7c4f5d27ce1dd1d811d1407"],
    ["SHA512", "54816905e95d0a740369d5fb40cc37ce13761d9f56e897508590faf2306152093147409290592b6aeddc694b2de4a816526be399e7bf50a971a1537df831ca4a"],
  ].each do |data|
    h = Digest::HMAC.new "key", Module.const_get("Digest").const_get(data[0])
    h.update "1"
    assert_equal h.hexdigest, data[1]
  end
end

