try:
    import tools
    print("Successfully imported tools")
    print(f"dir(tools): {dir(tools)}")
except Exception as e:
    print(f"Error importing tools: {e}")
    import traceback
    traceback.print_exc()
