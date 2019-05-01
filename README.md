# mini_httpd

Taken from <http://www.acme.com/software/mini_httpd/>

I made the commit history to show differences between versions. Forked from another repository because I'm kind of continuing their work.

Created using:

```
mkdir mini_httpd-1.10
cd mini_httpd-1.10
git init
cd ..
for i in {10..30}; do  # Files <1.10 do not appear to be online
	if [ ! -f "mini_httpd-1.$i.tar.gz" ]; then
		wget http://www.acme.com/software/mini_httpd/mini_httpd-1.$i.tar.gz
	fi
	tar xf mini_httpd-1.$i.tar.gz
	cd mini_httpd-1.$i
	git add .
	git commit -m "Add mini_httpd-1.$i"
	cd ..
	mv mini_httpd-1.$i mini_httpd-1.$(($i+1))
	sleep 1
done
```

Feel free to do a history-rewriting pull request (is that even possible?) if
you added the website's changelog to commit messages or something.

