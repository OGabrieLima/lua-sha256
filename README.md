
# Lua SHA-256 Hash Calculator

## Description
This Lua script implements the SHA-256 algorithm to calculate the hash of a message. SHA-256 is a widely used cryptographic hash function that produces a 256-bit (32-byte) hash value. This script provides a simple yet efficient way to calculate SHA-256 hashes in Lua.

The implementation follows the specifications outlined in the SHA-256 algorithm standard. For more information about SHA-256 and its applications, you can refer to the National Institute of Standards and Technology (NIST) publication [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).

## Installation
To use this script in your Lua projects, you can simply copy the `lua-sha256` file into your project directory and require it in your code:

1. **Download the script**: Download the `lua-sha256` file from the [GitHub repository](https://github.com/OGabrieLima/lua-sha256/releases).

2. **Copy to your project directory**: Place the `lua-sha256` folder in your Lua project directory.

3. **Require the script**: In your fxmanifest, require the `sha256` module:

```lua
server_script '*/lua_sha256/hash.lua'
```

## Usage
To calculate the SHA-256 hash of a message, use the `sha256` function:

```lua
local message = "Hello, world!"
local hash = sha256(message)
print("SHA-256 Hash of '" .. message .. "': " .. hash)
```

## Author
This script was created by [OGabrieLima](https://github.com/OGabrieLima). You can find more of their work on [GitHub](https://github.com/OGabrieLima).

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
