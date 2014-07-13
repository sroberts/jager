```
     ____.
    |    |____     ____   ___________
    |    \__  \   / ___\_/ __ \_  __ \
/\__|    |/ __ \_/ /_/  >  ___/|  | \/
\________(____  /\___  / \___  >__|
              \//_____/      \/        Hunting IOCs All Day Every Day
```

Jager is a tool for pulling useful IOCs (indicators of compromise) out of various input sources (PDFs for now, plane text really soon, webpages eventually) and putting them into an easy to manipulate JSON format. Who doesn't want that?!

## Short Comings
First of all there's some stuff Jager doesn't do (or does poorly):

- It doesn't do OCR, so CrowdStrikes annoying "Images only" PDFs don't work terribly well. That's why it's going to have text analysis, so you can OCR by hand and extract IOCs from the text.
- The regex's are fine, but they need some work. We'll see. Regexs are hard, lets go shopping.
- There are lots of things you can't regex, like group names or attribution. You'll have to do some of that by hand.

## Use:
To analyze a PDF:

```python jager.py -i foo.pdf -o bar.json```

To analyze a directory of PDFs:

```python jager.py -d ~/foo -o ~/bar```

## Features for the Future
- New Analysis Modes
    - Webpages
    - Plain Text
- New Indicator Types
    - URLs
    - File Paths
    - Registry Keys (Not super important to me, but they're a thing)
- More Useful Output
    - Write stuff out to a database (like Mongo *shudder*)
    - Write out to a TrackerSmacker:tm: DB
    - Data enrichment

## License
Assuming this is ever released (it may not be) check [LICENSE.md](./LICENSE.md) for information.

## Contributing
See above s/LICENSE/CONTRIBUTING/g.
