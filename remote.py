import random
import secrets
import json
import sys
import socket

BOARD_SIZE = 2**32
SHIP_SIZES = [5, 4, 3, 3, 2]
MAX_TURNS = 312

seed = secrets.randbits(64)
rng = random.Random(seed)
FLAG = open("./flag.txt","r").read()

print(rng.random.__doc__)
def place_ship(board, start_row, start_col, size, direction):
    positions = []
    for i in range(size):
        r = start_row + i if direction == 'V' else start_row
        c = start_col + i if direction == 'H' else start_col
        if not (0 <= r < BOARD_SIZE and 0 <= c < BOARD_SIZE):
            return False
        pos = (r, c)
        if pos in board:
            return False
        positions.append(pos)
    for pos in positions:
        board.add(pos)
    return True

def place_computer_ships():
    board = set()
    for size in SHIP_SIZES:
        placed = False
        r = rng.getrandbits(32)
        c = rng.getrandbits(32)
        print(f"R {r}")
        print(f"C {c}")
        rng_random = rng.random()
        print(f"RNG {rng_random}")
        #print(f"H: {(r << 32)| c}")
        d = 'H' if rng_random< 0.5 else 'V'
        placed = place_ship(board, r, c, size, d)
    return board

def parse_ship_input(data):
    try:
        print(f"Data: {data}")
        ships = json.loads(data)
        print(ships)
        if not isinstance(ships, list) or len(ships) != len(SHIP_SIZES):
            return None
        print("OK")
        parsed = []
        for entry in ships:
            if (not isinstance(entry, list) or len(entry) != 3 or
                not isinstance(entry[0], int) or not isinstance(entry[1], int) or
                entry[2] not in ("H", "V")):
                return None
            parsed.append((entry[0], entry[1], entry[2]))
        return parsed
    except:
        return None

def start_game(client_socket):
    #print("Starting new game.")
    #print("Enter your ship placements as JSON list (e.g. [[100,200,\"V\"], [300,400,\"H\"], ...])")
    #print(f"You must sink all computer ships in under {MAX_TURNS} moves.")
    client_socket.sendall(b"Starting new game.\n")
    client_socket.sendall(b"Enter your ship placements as JSON list (e.g. [[100,200,\"V\"], [300,400,\"H\"], ...])\n")
    client_socket.sendall(f"You must sink all computer ships in under {MAX_TURNS} moves.\n".encode())

    while True:
        #print("Ship placements:")
        client_socket.sendall(b"Ship placements:\n")
        #line = sys.stdin.readline()
        line = client_socket.recv(1024)
        if not line:
            return
        ships = parse_ship_input(line.strip())
        if not ships:
            #print("Invalid input. Must be a JSON list like [[r,c,\"H\"]].")
            client_socket.sendall(b"Invalid input. Must be a JSON list like [[r,c,\"H\"]].\n")
            continue
        break

    player_board = set()
    for idx, (r, c, d) in enumerate(ships):
        if not place_ship(player_board, r, c, SHIP_SIZES[idx], d):
            #print(f"Invalid placement for ship {idx+1}.")
            client_socket.sendall(f"Invalid placement for ship {idx+1}.\n".encode('utf-8'))
            return

    computer_board = place_computer_ships()
    player_shots = set()

    for turn in range(0, MAX_TURNS):
        #print(f"Turn {turn+1} - Enter your shot as row,col (e.g. 12345,67890):")
        client_socket.sendall(f"Turn {turn+1} - Enter your shot as row, col (e.g 12345,67890):\n".encode())
        #line = sys.stdin.readline()
        line = client_socket.recv(1024).decode()
        if not line:
            return
        try:
            sr, sc = map(int, line.strip().split(","))
        except:
            #print("Invalid input. Must be row,col format.")
            client_socket.sendall(b"Invalid input. Must be row, col format\n")
            continue

        if (sr, sc) in player_shots:
            client_socket.sendall(b"Already shot there.\n")
            #print("Already shot there.")
            continue

        player_shots.add((sr, sc))
        if (sr, sc) in computer_board:
            client_socket.sendall(b"HIT\n")
            #print("HIT")
        else:
            client_socket.sendall(b"MISS\n")
            #print("MISS")

        if computer_board.issubset(player_shots):
            client_socket.sendall(b"You sank all the computer's ships! You win.\n")
            client_socket.sendall(b"Flag: {FLAG}\n")
            #print("You sank all the computer's ships! You win.")
            #print(f"Flag: {FLAG}")
            return

        cr = rng.getrandbits(32)
        cc = rng.getrandbits(32)
        da = str(cr) + " " + str(cc)
        print(da)

        result = "HIT" if (cr, cc) in player_board else "MISS"
        client_socket.sendall(f"Computer fires at {cr},{cc} - {result}\n".encode())
        #print(f"Computer fires at {cr},{cc} - {result}")
    #print("You ran out of moves. Game over.")
    client_socket.sendall(b"You ran out of moves. Game over.\n")


print("== BATTLESHIP CTF ==")
print("Board size: 4,294,967,296 x 4,294,967,296")
print("Sink all computer ships in under 312 moves.")
print("Good luck.\n")

try:
    host = '0.0.0.0'
    port = 9001

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Server listening on 9001")
    client_socket, client_address = server_socket.accept()
    while True:
        start_game(client_socket)
        client_socket.sendall(b"Press enter to try again or type exit to quit\n")
    #print("Press enter to try again or type exit to quit")
    #cmd = input("> ")
        cmd = client_socket.recv(1024)
        if cmd.strip().lower() == "exit":
            raise KeyboardInterrupt
except KeyboardInterrupt:
    print("Shutting down server")
