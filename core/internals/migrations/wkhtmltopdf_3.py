__description__ = "Warning about 'wkhtmltopdf'"


def migrate():
    print(
        """

    # Note

    This update comes with a new investigation import feature that you can use
    to create investigations from URLs (from a blog post for example).

    The better user experience when importing from URLs comes if you have
    'wkhtmltopdf' installed and available in your PATH. This tool needs to be
    installed manually. You can get more information at https://wkhtmltopdf.org/.

    Installation on Ubuntu:

        $ sudo apt-get install wkhtmltopdf

    Installation on macOS:

        $ brew install wkhtmltopdf

    """
    )
