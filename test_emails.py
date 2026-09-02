"""Sample emails for exercising gemini_client.classify() across the
categories the triage tool needs to handle."""

TEST_EMAILS = [
    {
        "from": "jaylen.brooks04@gmail.com",
        "subject": "Class of 2027 - interested in the soccer program",
        "body": "Hi Coach, my name is Jaylen Brooks and I'm a "
                "class of 2027 center back from Columbus, Ohio. I play "
                "club for Ohio Elite SC and wanted to introduce myself "
                "and see what the recruiting process looks like for "
                "the program.",
    },
    {
        "from": "sofia.martins09@gmail.com",
        "subject": "Prospective 2028 recruit - forward",
        "body": "Hello Coach, I'm Sofia Martins, a 2028 forward playing "
                "for the Boston Bolts. I'd love to set up a call to learn "
                "more about the program and share some game film.",
    },
    {
        "from": "danielortiz22@gmail.com",
        "subject": "Updated fall schedule + highlight clip",
        "body": "Hi Coach, quick update - my ECNL schedule changed, our "
                "next few games are now the weekend of the 12th instead "
                "of the 5th. Also attaching a clip from last week's game "
                "where I scored twice. Let me know if you'll be able to "
                "make it out.",
    },
    {
        "from": "rebecca.chen.parent@gmail.com",
        "subject": "On behalf of my son Marcus Chen",
        "body": "Hi Coach, I'm Marcus Chen's mother - he's a "
                "junior midfielder who emailed you last month. He's a "
                "bit shy about reaching out too often so I wanted to "
                "follow up and ask whether you'll be at the showcase in "
                "October.",
    },
    {
        "from": "info@nutmegsoccercamps.org",
        "subject": "Question about summer camp pricing",
        "body": "Hello, I'm helping organize a group of players interested "
                "in attending your summer camp. Could you send over "
                "pricing for the overnight session versus the day session, "
                "and whether there's a discount for registering a group "
                "of 5 or more?",
    },
    {
        "from": "k.alvarez@collegesoccernews.com",
        "subject": "Interview request - preseason feature",
        "body": "Hi Coach, I'm a reporter with College Soccer News working "
                "on a preseason feature about NESCAC programs. Would you "
                "be available for a 15-minute phone interview sometime "
                "next week?",
    },
    {
        "from": "billing@fieldturfpro.com",
        "subject": "Invoice #38821 - Field maintenance, due 9/15",
        "body": "Attached is invoice #38821 for the field resurfacing "
                "work completed last week, total due $4,250.00 by "
                "September 15. Let us know if you have any questions "
                "about the line items.",
    },
    {
        # Genuinely ambiguous: no grad year, mentions a past camp *and*
        # asks a recruiting-adjacent question, doesn't cleanly fit any
        # one category.
        "from": "t.kowalski.soccer@gmail.com",
        "subject": "Question",
        "body": "Hey Coach, not sure if you remember me from the camp last "
                "summer but I had a question about the program. Also is "
                "there a walk-on tryout in the fall or is it only for "
                "recruited players? Thanks.",
    },
]
