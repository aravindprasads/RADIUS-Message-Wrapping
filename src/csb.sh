echo "cscope build started";find . -name  '*.[ch]' > cscope.files;ctags -L cscope.files;cscope -qb;echo "cscope completed";
