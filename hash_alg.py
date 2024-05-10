import struct


class SHA1:
    def __init__(self):
        # Ініціалізація змінних A,B,C,D,E
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0
        self.unprocessed = b''  # Буфер для зберігання неопрацьованих байтів
        self.message_byte_length = 0  # Лічильник байтів у повідомленні

    def update(self, arg):
        # Додаємо нові дані до обробки
        if isinstance(arg, str):  # Перевірка чи аргумент є рядком
            arg = arg.encode('utf-8')  # Кодування строки у байти
        self.message_byte_length += len(arg)  # Збільшення загальної довжини повідомлення
        self.unprocessed += arg  # Додавання нових байтів до буферу

        # Обробка всіх доступних 64-байтових шматків
        while len(self.unprocessed) >= 64:  # Поки є достатньо байтів для формування блоку
            self._process_chunk(self.unprocessed[:64])  # Обробка перших 64 байтів = 512 бітів
            self.unprocessed = self.unprocessed[64:]  # Видалення оброблених байтів з буфера

    def digest(self):
        # Завершення обробки та виведення результату хешування
        return self._produce_digest()

    def hexdigest(self):
        # Виведення хешу у вигляді шістнадцяткового числа
        return ''.join(format(x, '08x') for x in self.digest())  # Форматування і об'єднання значень

    def _produce_digest(self):
        # Фіналізація повідомлення та додавання бітової довжини
        message = self.unprocessed + b'\x80'  # Додавання 1 біта в кінець повідомлення

        # Додавання нулів для досягнення потрібної довжини
        '''
        self.message_byte_length + 1: Загальна довжина повідомлення плюс 1
        (self.message_byte_length + 1) % 64: Визначає, скільки байтів вже є у поточному блоці.
        56 - (self.message_byte_length + 1) % 64: Визначає, скільки байтів ще потрібно додати,
            щоб досягти 56 байтів у блоці
        ((56 - (self.message_byte_length + 1) % 64) % 64): Використання додаткового модуля 64
            враховує випадок, коли додавання 1 байту може зробити довжину рівною або вже
            перевищити 56 байтів у поточному блоці. Тоді переходимо на наступний блок і додаємо 0 до 56 байтів
        '''
        message += b'\x00' * ((56 - (self.message_byte_length + 1) % 64) % 64)

        message_bit_length = self.message_byte_length * 8  # Конвертація довжини повідомлення у біти
        message += struct.pack(b'>Q', message_bit_length)  # Додавання довжини повідомлення як 64-бітне велике число
        # Формат: > big-endian, Q unsigned long long
        # Обробка залишкових шматків повідомлення
        while len(message) >= 64:
            self._process_chunk(message[:64])
            message = message[64:]

        # Поертаємо кінцеві значення хеш-функції
        return [self.h0, self.h1, self.h2, self.h3, self.h4]

    def _process_chunk(self, chunk):
        # Перевірка на коректну довжину блоку
        if len(chunk) != 64:
            raise ValueError("Chunk must be exactly 64 bytes in length")

        # Розбивка блоку на 16 32-бітних слова
        # Формат: > big-endian, 16I 16 unsigned int, кожне по 32 біти
        w = list(struct.unpack('>16I', chunk))

        # 16 слів по 32 біт доповнюються до 80 слів
        # ^ xor
        for i in range(16, 79):
            w.append(self._left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        # Ініціалізація хеш-значень для циклу обробки
        a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

        # Основний цикл обробки 80 слів
        for i in range(0, 79):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))  # Логічна функція
                k = 0x5A827999  # Константа
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (d & (b | c))
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            # Оновлення змінних для наступного кроку
            a, b, c, d, e = ((self._left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                             a, self._left_rotate(b, 30), c, d)

        # Додавання хеш-значень після обробки блоку до результату
        # & 0xffffffff - застосування 32-бітної маски
        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        self.h4 = (self.h4 + e) & 0xffffffff

    def _left_rotate(self, n, b):
        # Виконання циклічного зсуву вліво
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

