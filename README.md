```
  _____           _           ______                  
 |  __ \         | |         |  ____|                 
 | |__) |   _ ___| |_ _   _  | |__ ___ _ __   ___ ___ 
 |  _  / | | / __| __| | | | |  __/ _ \ '_ \ / __/ _ \
 | | \ \ |_| \__ \ |_| |_| | | | |  __/ | | | (_|  __/
 |_|  \_\__,_|___/\__|\__, | |_|  \___|_| |_|\___\___|
                       __/ |                          
                      |___/                           
```

# Rusty_Fence

Rusty_Fence is an experimental Rust DNS ad-blocker. It was written as an exercise to learn Rust and practice writing concurrent network applications.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Usage

1. Clone the repository: `git clone https://github.com/your_username/rusty_fence.git`
2. Navigate to the project directory: `cd rusty_fence`
3. Build the project: `cargo build`
4. Run the project: `cargo run`

By default, Rusty_Fence listens on port `5300` and uses the `hosts/hosts.txt` file as its blocklist. You can specify a different port or blocklist file using command line options. Run `cargo run -- --help` for more information.

## Contributing

Contributions are welcome! If you find a bug or want to suggest a new feature, please open an issue on the [issue tracker](https://github.com/your_username/rusty_fence/issues). If you want to contribute code, fork the repository and submit a pull request. Before submitting a pull request, please make sure your code follows the project's coding standards and passes all tests.