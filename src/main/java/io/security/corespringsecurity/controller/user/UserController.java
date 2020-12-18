package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

	@Autowired
	private UserService userService;
	@Autowired
	private PasswordEncoder passwordEncoder;

	//==마이페이지 매핑==//
	@GetMapping(value="/mypage")
	public String myPage() throws Exception{
		return "user/mypage";
	}

	//==로그인 화면 매핑==//
	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	//==회원가입==//
	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {

		// 뷰에서 전달받은 DTO를 ModelMapper이용해 Account 엔티티 형태로 변환
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);

		// 뷰에서 넘어온 password는 평문이므로 암호화해서 넣어줌
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		//회원 생성
		userService.createUser(account);

		return "redirect:/";
	}


}
