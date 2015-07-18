rule http_requests
{
    strings:
        $get = "GET"
        $post = "POST"

    condition:
        $get or $post
}