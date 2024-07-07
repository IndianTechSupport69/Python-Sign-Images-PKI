Hello!

This is just a quick POC to sign an image with a private key (PKI) and validate it with the public key.

How to sign an image:
1. Run the main.py
2. Enter the path to the image or click on browse and select the image.
3. If you have a key pair (Public and private) then click browse and select the private key. If you dont have a pair leave it empty and it will generate a new key pair. (The new generated key pair will be stored in a folder called keys in the same folder where the main.py is located in)
4. Enter a name that you want the new image to be called.
5. Done!

How to validate if an image is authentic:
1. Run the validate.py
2. Enter the path of the image you want to validate or click on browse and select the image.
3. Enter the path of the Public key or click browse and select the public key.
4. Press validate, If the image is authentic it will display so if not it will say its not good :)
