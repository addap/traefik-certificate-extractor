import os
import errno
import json
import glob
from base64 import b64decode

def handle_file(file):
    # Read JSON file
    data = json.loads(open(file).read())
    data = data['mytlschallenge']

    # We always use acme v2
    if not ('acme-v02' in data['Account']['Registration']['uri']):
        raise ValueError("Only acme v2 supported")

    certs = data['Certificates']

    print('Certificate storage contains ' + str(len(certs)) + ' certificates')

    # Loop over all certificates
    for c in certs:
        name = c['domain']['main']
        privatekey = c['key']
        fullchain = c['certificate']
        # try:
        #     sans = c['domain']['SANs']
        # except KeyError:
        #     sans = None

        # Decode private key, certificate and chain
        privatekey = b64decode(privatekey).decode('utf-8')
        fullchain = b64decode(fullchain).decode('utf-8')
        start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
        cert = fullchain[0:start]
        chain = fullchain[start:]

        # Create domain directory if it doesn't exist
        directory = 'certs/' + name + '/'
        try:
            os.makedirs(directory)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise

        # Write private key, certificate and chain to file
        with open(directory + 'privkey.pem', 'w') as f:
            f.write(privatekey)

        with open(directory + 'cert.pem', 'w') as f:
            f.write(cert)

        with open(directory + 'chain.pem', 'w') as f:
            f.write(chain)

        with open(directory + 'fullchain.pem', 'w') as f:
            f.write(fullchain)

        # if sans:
        #     for name in sans:
        #         with open(directory + name + '.key', 'w') as f:
        #             f.write(privatekey)
        #         with open(directory + name + '.crt', 'w') as f:
        #             f.write(fullchain)
        #         with open(directory + name + '.chain.pem', 'w') as f:
        #             f.write(chain)

        print('Extracted certificate for: ' + name) # + (', ' + ', '.join(sans) if sans else ''))

if __name__ == "__main__":
    # Determine path to watch
    path = './data'

    # Create output directories if it doesn't exist
    try:
        os.makedirs('certs')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # Extract certificates from current file(s) before watching
    files = glob.glob(os.path.join(path, '*.json'))
    try:
        for file in files:
            print('Certificate storage found (' + os.path.basename(file) + ')')
            handle_file(file)
    except Exception as e:
        print(f'Error: {e}')
