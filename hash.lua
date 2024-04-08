--[[ 
  Author: OGabrieLima
  GitHub: https://github.com/OGabrieLima
  Discord: ogabrielima
  Description: This is a Lua script that implements the SHA-256 algorithm to calculate the hash of a message.
               It includes a helper function for right rotation (bitwise) and the main function `sha256`.
               The `sha256` function can be used to calculate the SHA-256 hash of a message.
  Creation Date: 2024-04-08
]]

-- Auxiliary function: right rotation (bitwise)
local function bit_ror(x, y)
  return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF
end

-- Main function: SHA256
sha256 = function(message)
  local k = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  }

  local function preprocess(message)
      local len = #message
      local bitLen = len * 8
      message = message .. "\128" -- append single '1' bit

      local zeroPad = 64 - ((len + 9) % 64)
      if zeroPad ~= 64 then
          message = message .. string.rep("\0", zeroPad)
      end

      -- append length
      message = message .. string.char(
          bitLen >> 56 & 0xFF,
          bitLen >> 48 & 0xFF,
          bitLen >> 40 & 0xFF,
          bitLen >> 32 & 0xFF,
          bitLen >> 24 & 0xFF,
          bitLen >> 16 & 0xFF,
          bitLen >> 8 & 0xFF,
          bitLen & 0xFF
      )

      return message
  end

  local function chunkify(message)
      local chunks = {}
      for i = 1, #message, 64 do
          table.insert(chunks, message:sub(i, i + 63))
      end
      return chunks
  end

  local function processChunk(chunk, hash)
      local w = {}

      for i = 1, 64 do
          if i <= 16 then
              w[i] = string.byte(chunk, (i - 1) * 4 + 1) << 24 |
                     string.byte(chunk, (i - 1) * 4 + 2) << 16 |
                     string.byte(chunk, (i - 1) * 4 + 3) << 8 |
                     string.byte(chunk, (i - 1) * 4 + 4)
          else
              local s0 = bit_ror(w[i - 15], 7) ~ bit_ror(w[i - 15], 18) ~ (w[i - 15] >> 3)
              local s1 = bit_ror(w[i - 2], 17) ~ bit_ror(w[i - 2], 19) ~ (w[i - 2] >> 10)
              w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
          end
      end

      local a, b, c, d, e, f, g, h = table.unpack(hash)

      for i = 1, 64 do
          local s1 = bit_ror(e, 6) ~ bit_ror(e, 11) ~ bit_ror(e, 25)
          local ch = (e & f) ~ ((~e) & g)
          local temp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
          local s0 = bit_ror(a, 2) ~ bit_ror(a, 13) ~ bit_ror(a, 22)
          local maj = (a & b) ~ (a & c) ~ (b & c)
          local temp2 = (s0 + maj) & 0xFFFFFFFF

          h = g
          g = f
          f = e
          e = (d + temp1) & 0xFFFFFFFF
          d = c
          c = b
          b = a
          a = (temp1 + temp2) & 0xFFFFFFFF
      end

      return (hash[1] + a) & 0xFFFFFFFF,
             (hash[2] + b) & 0xFFFFFFFF,
             (hash[3] + c) & 0xFFFFFFFF,
             (hash[4] + d) & 0xFFFFFFFF,
             (hash[5] + e) & 0xFFFFFFFF,
             (hash[6] + f) & 0xFFFFFFFF,
             (hash[7] + g) & 0xFFFFFFFF,
             (hash[8] + h) & 0xFFFFFFFF
  end

  message = preprocess(message)
  local chunks = chunkify(message)

  local hash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
  for _, chunk in ipairs(chunks) do
      hash = {processChunk(chunk, hash)}
  end

  local result = ""
  for _, h in ipairs(hash) do
      result = result .. string.format("%08x", h)
  end

  return result
end
-- Exemplo de uso
-- local mensagem = "Hello, world!"
-- local hash = sha256(mensagem)
-- print("Hash SHA-256 de '" .. mensagem .. "': " .. hash)

exports("sha256", sha256)
