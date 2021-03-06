from fastapi import FastAPI, BackgroundTasks, Response
from fastapi.responses import HTMLResponse


#ROUTES
from .routes.provider import router as ProviderRouter
from .routes.murtentry import router as MURTEntryRouter
from .routes.sdncontroller import router as SDNControllerRouter


tags_metadata = [
    {
        "name": "Provider",
        "description": "Operations with PROVIDERS",
    },
    {
        "name": "MURT",
        "description": "Manage MURTS",
        "externalDocs": {
            "description": "MUPI-PROXY external docs",
            "url": "https://github.com/RAULTG97/mupi-proxy",
        },
    },
    {
        "name": "SDNController",
        "description": "Operations with SDNController",
    },
]


app = FastAPI(
	openapi_tags=tags_metadata,
	title="MUPI-PROXY API",
    description="API REST FOR MUPI-PROXY PROJECT. HERE YOU CAN CONFIGURE THE PROXY",
    version="1.0",)

app.include_router(ProviderRouter, tags=["Provider"], prefix="/mupi-proxy/provider")
app.include_router(MURTEntryRouter, tags=["MURT"], prefix="/mupi-proxy/murtentry")
app.include_router(SDNControllerRouter, tags=["SDNController"], prefix="/mupi-proxy/sdncontroller")


@app.get("/", tags=["Root"], response_class=HTMLResponse)
async def read_items():
    html_content = """
    <html>
        <head>
            <title>mupi-proxy</title>
        </head>
        <h1>MUPI PROXY API</h1>
        <body>
            <h3>Welcome to Mupi-Proxy</h3>
            <ul>
              <li>Providers
                <ul>
                  <li><a href="http://127.0.0.1:8000/mupi-proxy/provider/">Get Providers</a></li>
                </ul>
              </li>
              <li>Murt Entries
                <ul>
                  <li><a href="http://127.0.0.1:8000/mupi-proxy/murtentry/">MURT Entries</a></li>
                </ul>
              </li>
            </ul>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/mupi-proxy", tags=["Root"], response_class=HTMLResponse)
async def read_items():
    html_content = """
    <html>
        <head>
            <title>mupi-proxy</title>
        </head>
        <h1>MUPI PROXY API</h1>
        <body>
            <h3>Welcome to Mupi-Proxy</h3>
            <ul>
              <li>Providers
                <ul>
                  <li><a href="http://127.0.0.1:8000/mupi-proxy/provider/">Get Providers</a></li>
                </ul>
              </li>
              <li>Murt Entries
                <ul>
                  <li><a href="http://127.0.0.1:8000/mupi-proxy/murtentry/">MURT Entries</a></li>
                </ul>
              </li>
            </ul>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)



#BACKGROUND TASKS
def write_notification(email: str, message=""):
    with open("log.txt", mode="w") as email_file:
        content = f"notification for {email}: {message}"
        email_file.write(content)


@app.post("/mupi-proxy/send-notification/{email}")
async def send_notification(email: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(write_notification, email, message="some notification")
    return {"message": "Notification sent in the background"}