# mdb-ui-kit

This directory contains the source of
[mdb-ui-kit](https://github.com/mdbootstrap/mdb-ui-kit) at the version we want
to use.

Having the source allows us to customize styles in the `.scss`, compile it into
a `.css` and use it. The `install.bash` script does all that using the `sass`
npm module in a Docker container.

This only updates the `.css` though, so if you change the version, you also have
to get the corresponding version of `.mdb.min.js` (and update the integrity
hashes in the `<script>` tags).
