import base64
import imghdr
import codecs
import os


def reconstruct_image():
    #read in data
    fileinput = open('evidence.txt', "r").read()

    #rotate the data
    rotated = codecs.decode(fileinput, 'rot_13')

    #reverse the data
    reversed_file = "". join(reversed(rotated))

    #decode the data
    decoded_file =base64.standard_b64decode(reversed_file)

    #creating the output file
    output = open("output", 'w+b')
    output.write(bytearray(decoded_file))
    output.close()

    #find the right file extension
    extensions = imghdr.what('output')

    #rename the output file with correct extension
    os.rename('output', "output." + extensions)


if __name__ == "__main__":
     reconstruct_image()




