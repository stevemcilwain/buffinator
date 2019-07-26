# buffinator
Stack based, remote buffer overflow python script template.

'''
    ____        _________             __            
   / __ )__  __/ __/ __(_)___  ____ _/ /_____  _____
  / __  / / / / /_/ /_/ / __ \/ __ `/ __/ __ \/ ___/
 / /_/ / /_/ / __/ __/ / / / / /_/ / /_/ /_/ / /    
/_____/\__,_/_/ /_/ /_/_/ /_/\__,_/\__/\____/_/   

	Author :Steve Mcilwain
	GitHub : https://github.com/stevemcilwain
'''

## Purpose
I created this script to help me study for the OSCP exam and write remote, stack buffer overflows from scratch.  

## Usage
I have the script broken out into phases, so the intent is you do one phase, like fuzzing, then you come back and add the result into a variable and move on to the next step.

As you go along, you comment out methods except the one you're on and save results from your work into variables used by the next phase.  

## What This Isn't
The script isn't intended to be fully automated or anything, just to save time in developing a custom script. You need basic understanding of stack-based buffer overflows to use it. This isn't a tutorial or learning tool, more of a time-saver and mental guide.

## Roadmap
I'll add more "protocol" methods as I practice, just point to the one you need in send_with().  The current stuff in the script was from my practice on SLMail 5.5.

Enjoy and contribute!
