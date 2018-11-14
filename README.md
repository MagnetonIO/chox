## Installation/Running
To install python3 on CentOS, please follow the steps in below link.
https://www.digitalocean.com/community/tutorials/how-to-install-python-3-and-set-up-a-local-programming-environment-on-centos-7

* `$ sudo yum install -y wireshark gcc libxml2 libxml2-devel libxslt libxslt-devel python-devel`
* `$ sudo groupadd wireshark`
* `$ sudo usermod -a -G wireshark centos`
* `$ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/dumpcap`

* `$ git clone https://magnetonio@bitbucket.org/magnetonio/chox.git
* create an empty database
	* Put sqlite path in config.py DevelopmentConfig() class
	* `$ export APP_SETTINGS="config.DevelopmentConfig"`
* `$ cd chox`
* `$ pip install -r requirements.txt`
* `$ cd app`
* `$ python app.py shell`
    * `>>> init_db()`
    * `>>> db.session.commit()`
   	* Default user admin/chox is now setup
* `$ python app.py runserver`




