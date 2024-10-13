sudo apt update -y
sudo apt install cargo mingw-w64 mingw-w64-common -y
export RUSTUP_INIT_SKIP_PATH_CHECK=yes
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup toolchain install nightly
rustup default nightly
rustup target add x86_64-pc-windows-gnu
rustup toolchain install nightly-x86_64-pc-windows-gnu
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.8 python3.8-venv -y
python3.8 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
sed -i 's/self\._server_version = f"Werkzeug\/{importlib\.metadata\.version('"'"'werkzeug'"'"')}"/self\._server_version=""/g' venv/lib64/python3.8/site-packages/werkzeug/serving.py
sed -i 's/self\._server_version = f"Werkzeug\/{importlib\.metadata\.version('"'"'werkzeug'"'"')}"/self\._server_version=""/g' venv/lib/python3.8/site-packages/werkzeug/serving.py
