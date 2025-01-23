from locust import HttpUser, TaskSet, task

class MyUser(HttpUser):
    def on_start(self):
        self.client.headers = {"Authorization": "admin@aol.com:0oVPkvwB9tbRe0dY7JF4Tp7JIS7DzloojAAU7ugjBZo="}

    @task
    def main_test(self):
        self.client.get("/user")
        self.client.get("/users")
