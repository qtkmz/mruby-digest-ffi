module Digest
  class Base
    alias length digest_length
    alias size digest_length
    alias to_s hexdigest
    alias << update
  end
end

