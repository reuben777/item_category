# Item Catalog Project

A python application showcasing: CRUD, Authentication (User login + API Basic Auth)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them
1. [Vagrant](https://www.vagrantup.com/)
2. [VirtualBox](https://www.virtualbox.org/)

#### How to install
Just read the docs ;)

### Installing/Preparing the project

A step by step series of examples that tell you have to get the project setup for deployment and use

Go to project's vagrant file

```
cd ~{project directory}/vagrant
```

Install vagrant from vagrant file

```
vagrant up
```

Log into vagrant VM

```
vagrant ssh
```

Go to catalog directory in VM

```
cd /vagrant/catalog
```

Load DB

```
python application_setup.py
```

Load Data into DB

```
python db_populate.py
```

## Deployment

After Installing/Setup.

1. Go to project directory
```
cd ~{project directory}/vagrant
```
2. Start vagrant (if not already start)
```
vagrant up
```
3. Login (if not already logged in)
```
vagrant ssh
```
4. Go to catalog directory(~/vagrant/catalog)
```
cd /vagrant/catalog
```
5. Run server
```
python application.py
```

Application will be live at [localhost:8000](http://localhost:8000)

## Built With

* [Flask](http://flask.pocoo.org/docs/0.12/) - The web framework used
* [Python](https://docs.python.org/2/index.html) - Base Coding Language
* [flask_httpauth](https://flask-httpauth.readthedocs.io) - API Authentication

## Authors

* **Reuben Groenewald** - *Full Work* - [reuben777](https://github.com/reuben777)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [Stackoverflow](https://stackoverflow.com/)
