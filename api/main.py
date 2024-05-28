import requests
import json


class VKApi:
    """Класс для взаимодействия с VK Api"""

    def __init__(self, access_token: str, api_version: str) -> None:
        self.api_endpoint = "https://api.vk.com/method"
        self.access_token = access_token
        self.version = api_version

    def get_photo_albums(self, owner_id: int) -> str:
        """Выводит список альбомов пользователя VK с их описанием

        Args:
            owner_id (int): ID пользователя ВК

        Returns:
            str: Информация об альбомах пользователя с их описанием\
                в человеко-читаемом виде
        """
        data = self._make_request(f"photos.getAlbums?owner_id={owner_id}")

        try:
            data["response"]
        except KeyError:
            return "Введен неверный ID"

        output = f"Фотоальбомы пользователя c ID: {owner_id}\n\n"
        for album in data["response"]["items"]:
            output += f"{album["title"]}\nОписание: {album["description"]}\n\n"
        return output

    def _make_request(self, request_endpoint: str) -> dict:
        endpoint = f"{self.api_endpoint}/{request_endpoint}&access_token={
            self.access_token}&v={self.version}"
        response = requests.get(endpoint, timeout=1)
        data = response.json()
        return data


def main():
    with open("config.json", mode="rb") as file:
        data = json.load(file)
        token, version = data["token"], data["version"]

    api = VKApi(token, version)
    print(api.get_photo_albums(56719936))


if __name__ == "__main__":
    main()
