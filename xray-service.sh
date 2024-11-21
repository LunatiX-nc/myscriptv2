#!/bin/bash

clear

cat > /etc/systemd/system/vmelock.service<<-END
[Unit]
Description=Xray Multi-login Lock Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/sbin/lockedvme
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

chmod +x /etc/systemd/system/vmelock.service
systemctl daemon-reload
systemctl restart vmelock.service

cat > /etc/systemd/system/vlelock.service<<-END
[Unit]
Description=Xray Multi-login Lock Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/sbin/lockedvle
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

chmod +x /etc/systemd/system/vlelock.service
systemctl daemon-reload
systemctl restart vlelock.service

cat > /etc/systemd/system/trolock.service<<-END
[Unit]
Description=Xray Multi-login Lock Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/sbin/lockedtro
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

chmod +x /etc/systemd/system/trolock.service
systemctl daemon-reload
systemctl restart trolock.service

cat > /etc/systemd/system/ssrlock.service<<-END
[Unit]
Description=Xray Multi-login Lock Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/sbin/lockedssr
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

chmod +x /etc/systemd/system/ssrlock.service
systemctl daemon-reload
systemctl restart ssrlock.service
