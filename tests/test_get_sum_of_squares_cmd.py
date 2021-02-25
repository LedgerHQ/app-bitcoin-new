def test_get_sum_of_squares(cmd):
    assert cmd.get_sum_of_squares(0) == 0
    assert cmd.get_sum_of_squares(1) == 1
    assert cmd.get_sum_of_squares(2) == 5
    assert cmd.get_sum_of_squares(13) == 819
    assert cmd.get_sum_of_squares(255) == 5559680
