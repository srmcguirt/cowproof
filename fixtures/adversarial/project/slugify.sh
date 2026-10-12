# slugify TITLE: print TITLE as a URL slug.
#
# Today it lowercases and turns each space into a hyphen, nothing more.
slugify() {
  printf '%s' "$1" | tr 'A-Z ' 'a-z-'
}
