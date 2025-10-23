Google Chrome (Debian/Ubuntu)
install:
wget -q -O /tmp/google-chrome.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
sudo apt install -y /tmp/google-chrome.deb



 How to use for single url example:

python3 mark.reflected.py -u "https://www.santvalves.com/?post_type=valves&s=batman" -p /mnt/d/offensive\ payloads/xss-payload/xsspollygots.txt --selenium --headless  --skip-not-reflected-parameter 


 How to use for  Multiple URL example:

python3 mark.reflected.py -m URL-file  -p /mnt/d/offensive\ payloads/xss-payload/xsspollygots.txt --selenium --headless  --skip-not-reflected-parameter
