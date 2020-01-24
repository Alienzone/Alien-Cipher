# A ENCRYPTION - Version 0.1
# 64 * 8 bits ~ 64 Bytes/512 bits 
# THIS WAS WRITTEN BY ALIEN - alienzone@null.net - 17-06-2018-0222
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0 International License.
# To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/3.0/.

In laymans terms, we're generating output that is the result of adding up a lot of hashes and mixing 
them with both a rotating key and a message in a way that can be reversed if we know the key.

The strength is found when trying to reverse the output to the original factors. The random-based 
seeding of the hashing ensures we never get the same output twice.

The entropy in the chained hashes ensures that outside observers are unable to reverse the calculations 
in reasonable times due to the shear volume of combinations that can produce the result, whereas only 
the correct combinations can decode it.

Double-chaining the hashes grants integrity during the lifetime of the message chain by acting as a 
process-of-validation for the message key, ensuring the entire sequence is validated by the key space.

Adding salt and spices allows us to increase the overall entropy of the output and generate a more 
chaotic movement throughout the number space.

At the deepest level we're taking a 8x8 grid and filling the cells with our parameters. Although the 
cells fill up in a linear fashion across the grid the hash chains do not follow this pattern and instead
follows a diagonal movement across the grid, stepping side to side across the diagonal logically. 

By chaining the hashes of 2 previous cells per cell allows us to validate and scramble the cell with 
more entropy and more certainty that the cracker requires the breaking of 2 hashes together to defeat
the hash encoding. However unlikely this event decrypted data at this stage is still not decrypted. 

The result of the hashes from the salt, the nonce number and the keys are further tumbled and rotated
between blocks of cells. The small-nonce number(sn) for example provides the number of rotations a key
performs after adding itself to the key hash generated earlier. The seed-nonce number(NN) is also hashed
and incremented during the block rotations.

All these paramaters are required during the encoding/decoding calculations and they must be byte perfect.
The method is not fault tolerent to byte errors and will render garbage as a result. Can the garbage be used
to reverse the hashes? heh heh. This is where it gets interesting.

Although the cipher renders unique output when the same message and key is used, you would think that an incorrect 
key would render the same garbage on output when these uniques are incorrectly decoded. This is the interesting thing
about the chaotic movement in the outputs, only the correct sequences will resolve to deterministic output and every
thing else remains in chaos. 

In practice this cipher has proven to be effective at encoding a real-time duplex transmission of text over a 
websocket in reasonable amounts of time and provides the backbone to services running at http://aliens.us.to 
and http://alienzonexivmqro.onion. More on that later.....

For now this standalone version showcases the main components of the algorithm and how they operate.

Please note that I make no claims to this being a safe form of encryption. 
Cheers o7.
