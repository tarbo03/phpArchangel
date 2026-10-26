import argparse
from .dashboard import ArchangelDashboard

def main():
    p = argparse.ArgumentParser(description='phpArchangel Rich hybrid UI')
    p.add_argument('--splash', action='store_true', help='Try terminal inline graphics before opening Rich dashboard')
    args = p.parse_args()
    ArchangelDashboard().run(splash=args.splash)

if __name__ == '__main__':
    main()
