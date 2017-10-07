# Yeti - Community contributions

You've found Yeti useful, but somehow it's missing something crucial. Maybe
you filed an issue, or maybe you've written your own code and are ready to
share it with the world. Ideally, you've made a PR (it's better for everyone).
Here's a couple of things to take into consideration before submitting it.

## Core contributions

Yeti's core has grown to be quite large, and sometimes people submit interesting
changes or new features. We want to take the time to review these, both in
quality and relevance:

* Quality: We don't have a strict style guide (yet?), but the code has to be
  as clear and concise as possible.
  * Ideally, it will follow PEP8 (it will make it easier for us when we decide
    to apply a style guide to the whole project)
* Relevance: We understand that everyone has different needs, but Yeti's mission
  is quite clear and we don't want it to become too specialized. If it makes
  sense for nearly the whole userbase to have your changes pulled in, they will.

## Contributing plugins

The most things people contribute to Yeti are feeds, analytics, etc. Since we
can't possibly maintain everyone's code, we've decided to put these in a
contrib directory, so that the "use-at-your-own-risk" aspect of the plugin is
emphasized, and we hopefully get less issues over code we haven't written.

Of course, the criteria describe in "Core contributions" still applies, but
ultimately it's your code.

Please structure your contribution in this way, it will make it much easier to
test and merge:

```
contrib
├── README.md
└── feeds                     # Could also be "analytics", create it if you must.
    └── my_feed               # Your main contribution directory. Your code goes in here.
        ├── my_feed.py        # 1. The core of your contribution!
        ├── config.txt        # 2. Any extra configuration sections that need to go in the config file.
        ├── requirements.txt  # 3. Any additional python library your code uses.
        └── README.md         # Please provide a descirption & explanation on how to install your plugin.
```

After you're all set, submit your PR and let us review your code!
