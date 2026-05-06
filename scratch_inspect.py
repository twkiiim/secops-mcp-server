import os
import sys
from dotenv import load_dotenv
load_dotenv()

from utils import get_chronicle_client

def main():
    client = get_chronicle_client()
    if client is None:
        print("Failed to get chronicle client")
        return
    
    print(f"Client type: {type(client)}")
    print(f"Real chronicle type: {type(client.real_chronicle)}")
    print("Methods on real chronicle:")
    for attr in dir(client.real_chronicle):
        if not attr.startswith('_'):
            print(attr)

if __name__ == "__main__":
    main()
