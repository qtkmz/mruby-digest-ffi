assert("MD5 hexdigest") do
  d = Digest::MD5.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "c4ca4238a0b923820dcc509a6f75849b"
end

assert("RMD160 hexdigest") do
  d = Digest::RMD160.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "c47907abd2a80492ca9388b05c0e382518ff3960"
end

assert("SHA1 hexdigest") do
  d = Digest::SHA1.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "356a192b7913b04c54574d18c28d46e6395428ab"
end

assert("SHA256 hexdigest") do
  d = Digest::SHA256.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
end

assert("SHA384 hexdigest") do
  d = Digest::SHA384.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776"
end

assert("SHA512 hexdigest") do
  d = Digest::SHA512.new
  d.update "1"

  assert_equal d.digest.bytes.map{|c| "%02x" % c}.join, "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"
end

assert("MD5 hexdigest") do
  d = Digest::MD5.new
  d.update "1"

  assert_equal d.hexdigest, "c4ca4238a0b923820dcc509a6f75849b"
end

assert("RMD160 hexdigest") do
  d = Digest::RMD160.new
  d.update "1"

  assert_equal d.hexdigest, "c47907abd2a80492ca9388b05c0e382518ff3960"
end

assert("SHA1 hexdigest") do
  d = Digest::SHA1.new
  d.update "1"

  assert_equal d.hexdigest, "356a192b7913b04c54574d18c28d46e6395428ab"
end

assert("SHA256 hexdigest") do
  d = Digest::SHA256.new
  d.update "1"

  assert_equal d.hexdigest, "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
end

assert("SHA384 hexdigest") do
  d = Digest::SHA384.new
  d.update "1"

  assert_equal d.hexdigest, "47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776"
end

assert("SHA512 hexdigest") do
  d = Digest::SHA512.new
  d.update "1"

  assert_equal d.hexdigest, "4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a"
end

