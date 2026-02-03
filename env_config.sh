mkdir /run/mysshd
chown root:sys /run/mysshd
chmod 755 /run/mysshd
groupadd mysshd
useradd -g mysshd -c 'sshd privsep' -d /run/mysshd -s /bin/false mysshd
