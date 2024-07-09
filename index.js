
const canvas = document.getElementById("chess");
const ctx = canvas.getContext("2d");

const grid = [
    [1, 2, 3, 4, 5, 6, 7, 8],
    [16, 15, 14, 13, 12, 11, 10, 9],
    [17, 18, 19, 20, 21, 22, 23, 24],
    [32, 31, 30, 29, 30, 27, 26, 25],
    [33, 34, 35, 36, 37, 38, 39, 40],
    [48, 47, 46, 45, 44, 43, 42, 41],
    [49, 50, 51, 52, 53, 54, 55, 56],
    [64, 63, 62, 61, 60, 59, 58, 57],
]

const width = 500 / 8;
const height = 500 / 8;
let count = 1;

class Board {

    constructor(first_color, second_color) {
        this.first_color = first_color;
        this.second_color = second_color;
        this.pieces = ["w_rook", "b_rook", "w_knight", "b_knight", "w_bishop", "b_bishop", "w_queen",
            "b_queen", "w_king", "b_king", "w_pawn", "b_pawn"]
    }

    obj = {}

    drawBoard = () => {

        const boardletters = ["h", "g", "f", "e", "d", "c", "b", "a"];

        //draw the board
        for (let row = 0; row < 8; row++) {
            for (let col = 0; col < 8; col++) {
                this.obj[`${boardletters[row] + [col + 1]}`] = { x: row, y: col }
                let index = grid[row][col];
                if (index % 2 === 0) {
                    ctx.fillStyle = this.first_color;
                    ctx.fillRect(col * width, row * height, width, height);
                } else {
                    ctx.fillStyle = this.second_color;
                    ctx.fillRect(col * width, row * height, width, height);
                }

            }

        }

        //dispaly numbers and letters on board
        for (let i = 0; i < 8; i++) {
            let num = i + 1
            ctx.font = "11pt Arial";
            ctx.fillText(boardletters[i], (i * width) + 52, 495);
            if (i % 2 === 0) {
                ctx.fillStyle = this.first_color;
            } else {
                ctx.fillStyle = this.second_color;
            }
            ctx.fillText(num.toString(), 3, (i * height) + 15);
        }



    }

    //Load the pieces into canvas

    load_pieces = () => {

        for (let i = 0; i < 16; i++) {
            const piece = new Image();
            piece.src = `./img/${this.pieces[i]}.png`;
            piece.onload = () => {
                switch (this.pieces[i]) {
                    case "w_rook":
                        ctx.drawImage(piece, this.obj.h8.x * width, this.obj.h8.y * height);
                        ctx.drawImage(piece, this.obj.a8.x * width, this.obj.a8.y * height);
                        this.obj.h8["piece"] = "w_rook";
                        this.obj.a8["piece"] = "w_rook"
                        break;
                    case "b_rook":
                        ctx.drawImage(piece, this.obj.h1.x * width, this.obj.h1.y * height);
                        ctx.drawImage(piece, this.obj.a1.x * width, this.obj.a1.y * height);
                        this.obj.h1["piece"] = "b_rook";
                        this.obj.a1["piece"] = "b_rook";
                        break;
                    case "w_knight":
                        ctx.drawImage(piece, this.obj.g8.x * width, this.obj.g8.y * height);
                        ctx.drawImage(piece, this.obj.b8.x * width, this.obj.b8.y * height);
                        this.obj.g8["piece"] = "w_knight";
                        this.obj.b8["piece"] = "w_knight";
                    case "b_knight":
                        ctx.drawImage(piece, this.obj.g1.x * width, this.obj.g1.y * height);
                        ctx.drawImage(piece, this.obj.b1.x * width, this.obj.b1.y * height);
                        this.obj.g1["piece"] = "b_knight";
                        this.obj.b1["piece"] = "b_knight";
                        break;
                    case "w_bishop":
                        ctx.drawImage(piece, this.obj.f8.x * width, this.obj.f8.y * height);
                        ctx.drawImage(piece, this.obj.c8.x * width, this.obj.c8.y * height);
                        this.obj.f8["piece"] = "w_bishop";
                        this.obj.c8["piece"] = "w_bishop";
                        break;
                    case "b_bishop":
                        ctx.drawImage(piece, this.obj.f1.x * width, this.obj.f1.y * height);
                        ctx.drawImage(piece, this.obj.c1.x * width, this.obj.c1.y * height);
                        this.obj.f1["piece"] = "b_bishop";
                        this.obj.c1["piece"] = "b_bishop";
                        break;
                    case "w_king":
                        ctx.drawImage(piece, this.obj.e8.x * width, this.obj.e8.y * height);
                        this.obj.e8["piece"] = "w_king";
                        break;
                    case "b_king":
                        ctx.drawImage(piece, this.obj.e1.x * width, this.obj.e1.y * height);
                        this.obj.e1["piece"] = "b_king";
                        break;
                    case "w_queen":
                        ctx.drawImage(piece, this.obj.d8.x * width, this.obj.d8.y * height);
                        this.obj.d8["piece"] = "w_queen";
                        break;
                    case "b_queen":
                        ctx.drawImage(piece, this.obj.d1.x * width, this.obj.d1.y * height);
                        this.obj.d1["piece"] = "b_queen";
                        break;
                    case "w_pawn":
                        ctx.drawImage(piece, this.obj.h7.x * width, this.obj.h7.y * height);
                        this.obj.h7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.g7.x * width, this.obj.g7.y * height);
                        this.obj.g7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.f7.x * width, this.obj.f7.y * height);
                        this.obj.f7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.e7.x * width, this.obj.e7.y * height);
                        this.obj.e7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.d7.x * width, this.obj.d7.y * height);
                        this.obj.d7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.c7.x * width, this.obj.c7.y * height);
                        this.obj.c7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.b7.x * width, this.obj.b7.y * height);
                        this.obj.b7["piece"] = "w_pawn";
                        ctx.drawImage(piece, this.obj.a7.x * width, this.obj.a7.y * height);
                        this.obj.a7["piece"] = "w_pawn";
                        break;

                    case "b_pawn":
                        ctx.drawImage(piece, this.obj.h2.x * width, this.obj.h2.y * height);
                        this.obj.h2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.g2.x * width, this.obj.g2.y * height);
                        this.obj.g2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.f2.x * width, this.obj.f2.y * height);
                        this.obj.f2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.e2.x * width, this.obj.e2.y * height);
                        this.obj.e2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.d2.x * width, this.obj.d2.y * height);
                        this.obj.d2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.c2.x * width, this.obj.c2.y * height);
                        this.obj.c2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.b2.x * width, this.obj.b2.y * height);
                        this.obj.b2["piece"] = "b_pawn";
                        ctx.drawImage(piece, this.obj.a2.x * width, this.obj.a2.y * height);
                        this.obj.a2["piece"] = "b_pawn";
                        break;
                }
            }
        }


    }

    check_pos_piece = {
        x: "",
        y: "",
        square: "",
        type: "",
    }



    possible_movements = () => {
        let type_piece = this.check_pos_piece.type;
        //let posX = this.check_pos_piece.x;
        //let posY = this.check_pos_piece.y;
        let posX = 0;
        let posY = 0;

        if (type_piece.includes("rook")) {
            //Check possible squares 
            for (let key in this.obj) {
                let key_x = this.obj[key].x;
                let key_y = this.obj[key].y
                if (key_x === posX && !(key_x === posX && key_y === posY) && this.obj[key].piece == null) {
                    let key_xy = key_x * key_y
                    let danger = 0;
                    for (let check_key in this.obj) {
                        let check_key_xy = this.obj[check_key].x * this.obj[check_key].y
                        let piece_pos = posX * posY
                        if (this.obj[check_key].x == posX && this.obj[check_key].piece != null && key_xy < check_key_xy && check_key_xy < piece_pos) {
                            danger = 1;
                        }
                        if (this.obj[check_key].x == posX && this.obj[check_key].piece != null && key_xy > check_key_xy && check_key_xy > piece_pos) {
                            danger = 1;
                        }
                    }
                    if (danger == 0) {
                        ctx.fillStyle = "red";
                        ctx.fillRect(key_x * width, key_y * height, width, height);
                    }
                } else if (key_y === posY && !(key_x === posX && key_y === posY) && this.obj[key].piece == null) {
                    let key_xy = key_x * key_y
                    let danger = 0;
                    for (let check_key in this.obj) {
                        let check_key_xy = this.obj[check_key].x * this.obj[check_key].y
                        let piece_pos = posX * posY
                        if (this.obj[check_key].y == posY && this.obj[check_key].piece != null && key_xy < check_key_xy && check_key_xy < piece_pos) {
                            danger = 1;
                        }
                        if (this.obj[check_key].y == posY && this.obj[check_key].piece != null && key_xy > check_key_xy && check_key_xy > piece_pos) {
                            danger = 1;
                        }
                    }
                    if (danger == 0) {
                        ctx.fillStyle = "red";
                        ctx.fillRect(key_x * width, key_y * height, width, height);
                    }
                }
            }
            //Knight possible positions
        } else if (type_piece.includes("knight")) {
            for (let pos_square in this.obj) {
                let pos_square_x = this.obj[pos_square].x
                let pos_square_y = this.obj[pos_square].y

                if (pos_square_x + 2 == posX && pos_square_y + 1 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x - 2 == posX && pos_square_y + 1 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x + 1 == posX && pos_square_y + 2 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x - 1 == posX && pos_square_y + 2 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x + 2 == posX && pos_square_y - 1 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x + 1 == posX && pos_square_y - 2 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x - 2 == posX && pos_square_y - 1 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

                if (pos_square_x - 1 == posX && pos_square_y - 2 == posY) {
                    ctx.fillStyle = "red";
                    ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                }

            }

        } else if (type_piece.includes("bishop")) {
            if (this.check_pos_piece.square == "c8" || this.check_pos_piece.square == "f1") {
                for (let pos_square in this.obj) {
                    let pos_square_x = this.obj[pos_square].x;
                    let pos_square_y = this.obj[pos_square].y;

                    if (posX == posY && pos_square_x == pos_square_y && posX % 2 == 0) {
                        ctx.fillStyle = "red";
                        ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                    }

                    for (let count = 2; count < 14; count = count + 2) {
                        if (posY + posX == count && pos_square_x + pos_square_y == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }

                        if (posY - posX == count && pos_square_y - pos_square_x == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }

                        if (posX - posY == count && pos_square_x - pos_square_y == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }

                    }

                    //if (posY + posX == 8 && pos_square_x + pos_square_y == 8 && posX % 2 == 0) {
                    //ctx.fillStyle = "red";
                    //ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                    //}

                }
            } else if (this.check_pos_piece.square == "f8" || this.check_pos_piece.square == "c1") {
                for (let pos_square in this.obj) {
                    let pos_square_x = this.obj[pos_square].x;
                    let pos_square_y = this.obj[pos_square].y;
                    for (let count = 1; count < 14; count++) {
                        if (posX + posY == count && pos_square_x + pos_square_y == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }

                        if (posX - posY == count && pos_square_x - pos_square_y == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }

                        if (posY - posX == count && pos_square_y - pos_square_x == count) {
                            ctx.fillStyle = "red";
                            ctx.fillRect(pos_square_x * width, pos_square_y * height, width, height);
                        }
                    }
                }
            }
        }
    }

    listen = () => {
        canvas.addEventListener("click", (e) => {
            let mouseX = e.offsetX;
            let mouseY = e.offsetY;
            for (let key in this.obj) {
                let posX = this.obj[key].x; //get square x coordinate
                let posY = this.obj[key].y; // get square y coordinate
                if ((posX * width + width) > mouseX && (posY * height + height) > mouseY && (posX * width) < mouseX && (posY * width) < mouseY && this.obj[key].piece != null) {
                    this.check_pos_piece.x = posX
                    this.check_pos_piece.y = posY
                    this.check_pos_piece.square = key
                    this.check_pos_piece.type = this.obj[key].piece
                    ctx.fillStyle = "lightgreen";
                    ctx.fillRect(this.obj[key].x * width, this.obj[key].y * height, width, height);
                    const piece = new Image();
                    piece.src = `./img/${this.obj[key].piece}.png`
                    piece.onload = () => { ctx.drawImage(piece, this.obj[key].x * width, this.obj[key].y * height) };
                    this.possible_movements()
                }
            }

        })
    }


}



const chess_board = new Board("green", "white");
chess_board.drawBoard();
chess_board.load_pieces();
chess_board.listen();


