def run_command(user_input):
    # vulnerable to command injection
    import os
    os.system(f"ls {user_input}")


def main():
    user = input('enter path: ')
    run_command(user)

if __name__ == '__main__':
    main()
